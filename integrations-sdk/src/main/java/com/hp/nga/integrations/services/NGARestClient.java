package com.hp.nga.integrations.services;

import com.hp.nga.integrations.dto.DTOFactory;
import com.hp.nga.integrations.dto.configuration.CIProxyConfiguration;
import com.hp.nga.integrations.dto.configuration.NGAConfiguration;
import com.hp.nga.integrations.dto.connectivity.NGAHttpMethod;
import com.hp.nga.integrations.dto.connectivity.NGARequest;
import com.hp.nga.integrations.dto.connectivity.NGAResponse;
import com.hp.nga.integrations.SDKManager;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.*;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.http.Header;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by gullery on 14/01/2016.
 * <p/>
 * REST Client default implementation
 */

final class NGARestClient {
	private static final Logger logger = LogManager.getLogger(NGARestClient.class);
	private static final Set<Integer> AUTHENTICATION_ERROR_CODES;
	private static final String CLIENT_TYPE_HEADER = "HPECLIENTTYPE";
	private static final String CLIENT_TYPE_VALUE = "HPE_CI_CLIENT";
	private static final String LWSSO_COOKIE_NAME = "LWSSO_COOKIE_KEY";
	private static final String CSRF_COOKIE_NAME = "HPSSO_COOKIE_CSRF";
	private static final String CSRF_HEADER_NAME = "HPSSO_HEADER_CSRF";

	private static final String AUTHENTICATION_URI = "authentication/sign_in";
	private static final String AUTHENTICATION_HEADER = "Authorization";
	private static final String AUTHENTICATION_BASIC_PREFIX = "Basic ";

	private final SDKManager manager;
	private final CloseableHttpClient httpClient;
	private int MAX_TOTAL_CONNECTIONS = 20;
	private CookieStore cookieStore;
	private Cookie LWSSO_TOKEN = null;
	private String CSRF_TOKEN = null;

	static {
		AUTHENTICATION_ERROR_CODES = new HashSet<Integer>();
		AUTHENTICATION_ERROR_CODES.add(HttpStatus.SC_UNAUTHORIZED);
	}

	NGARestClient(SDKManager manager) {
		this.manager = manager;
		PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
		connectionManager.setMaxTotal(MAX_TOTAL_CONNECTIONS);
		connectionManager.setDefaultMaxPerRoute(MAX_TOTAL_CONNECTIONS);
		cookieStore = new BasicCookieStore();

		HttpClientBuilder clientBuilder = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.setDefaultCookieStore(cookieStore);

		CIProxyConfiguration proxyConf = manager.getCIPluginServices().getProxyConfiguration();
		if (proxyConf != null) {
			logger.warn("proxy will be used with the following setup: " + proxyConf);
			HttpHost proxyHost = new HttpHost(proxyConf.getHost(), proxyConf.getPort());

			clientBuilder
					.setProxy(proxyHost);

			if (proxyConf.getUsername() != null && !proxyConf.getUsername().isEmpty()) {
				AuthScope authScope = new AuthScope(proxyHost);
				Credentials credentials = new UsernamePasswordCredentials(proxyConf.getUsername(), proxyConf.getPassword());
				CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
				credentialsProvider.setCredentials(authScope, credentials);

				clientBuilder
						.setDefaultCredentialsProvider(credentialsProvider);
			}
		}

		httpClient = clientBuilder.build();
	}

	NGAResponse execute(NGARequest request) {
		return executeInternal(request, manager.getCIPluginServices().getNGAConfiguration());
	}

	NGAResponse execute(NGARequest request, NGAConfiguration configuration) {
		return executeInternal(request, configuration);
	}

	private NGAResponse executeInternal(NGARequest request, NGAConfiguration configuration) {
		NGAResponse result;
		HttpClientContext context;
		HttpUriRequest uriRequest;
		HttpResponse httpResponse = null;
		NGAResponse loginResponse;
		if (LWSSO_TOKEN == null) {
			logger.warn("initial login");
			loginResponse = login(configuration);
			if (loginResponse.getStatus() != 200) {
				logger.error("failed on initial login, status " + loginResponse.getStatus());
				throw new RuntimeException("failed on initial login, status " + loginResponse.getStatus());
			}
		}

		try {
			uriRequest = createHttpRequest(request);
			context = createHttpContext();
			httpResponse = httpClient.execute(uriRequest, context);

			if (AUTHENTICATION_ERROR_CODES.contains(httpResponse.getStatusLine().getStatusCode())) {
				logger.warn("re-login");
				HttpClientUtils.closeQuietly(httpResponse);
				loginResponse = login(configuration);
				if (loginResponse.getStatus() != 200) {
					logger.error("failed on re-login, status " + loginResponse.getStatus());
					throw new RuntimeException("failed on re-login, status " + loginResponse.getStatus());
				}
				uriRequest = createHttpRequest(request);
				context = createHttpContext();
				httpResponse = httpClient.execute(uriRequest, context);
			}

			result = createNGAResponse(httpResponse);
		} catch (IOException ioe) {
			logger.error("failed executing " + request, ioe);
			throw new RuntimeException("failed executing " + request, ioe);
		} finally {
			if (httpResponse != null) {
				HttpClientUtils.closeQuietly(httpResponse);
			}
		}

		return result;
	}

	private HttpUriRequest createHttpRequest(NGARequest ngaRequest) {
		RequestBuilder requestBuilder;

		//  create base request by METHOD
		if (ngaRequest.getMethod().equals(NGAHttpMethod.GET)) {
			requestBuilder = RequestBuilder
					.get(ngaRequest.getUrl());
		} else if (ngaRequest.getMethod().equals(NGAHttpMethod.DELETE)) {
			requestBuilder = RequestBuilder
					.delete(ngaRequest.getUrl());
		} else if (ngaRequest.getMethod().equals(NGAHttpMethod.POST)) {
			try {
				requestBuilder = RequestBuilder
						.post(ngaRequest.getUrl())
						.setEntity(new StringEntity(ngaRequest.getBody()));
			} catch (UnsupportedEncodingException uee) {
				logger.error("failed to create POST entity", uee);
				throw new RuntimeException("failed to create POST entity", uee);
			}
		} else if (ngaRequest.getMethod().equals(NGAHttpMethod.PUT)) {
			try {
				requestBuilder = RequestBuilder
						.put(ngaRequest.getUrl())
						.setEntity(new StringEntity(ngaRequest.getBody()));
			} catch (UnsupportedEncodingException uee) {
				logger.error("failed to create PUT entity", uee);
				throw new RuntimeException("failed to create PUT entity", uee);
			}
		} else {
			throw new RuntimeException("HTTP method " + ngaRequest.getMethod() + " not supported");
		}

		//  set custom headers
		if (ngaRequest.getHeaders() != null) {
			for (Map.Entry<String, String> e : ngaRequest.getHeaders().entrySet()) {
				requestBuilder.setHeader(e.getKey(), e.getValue());
			}
		}

		//  set system headers
		requestBuilder.setHeader(CLIENT_TYPE_HEADER, CLIENT_TYPE_VALUE);
		requestBuilder.setHeader(CSRF_HEADER_NAME, CSRF_TOKEN);

		return requestBuilder.build();
	}

	private HttpClientContext createHttpContext() {
		HttpClientContext context = HttpClientContext.create();
		CookieStore localCookies = new BasicCookieStore();
		localCookies.addCookie(LWSSO_TOKEN);
		context.setCookieStore(localCookies);
		return context;
	}

	private NGAResponse createNGAResponse(HttpResponse response) throws IOException {
		NGAResponse ngaResponse = DTOFactory.getInstance().newDTO(NGAResponse.class)
				.setStatus(response.getStatusLine().getStatusCode());
		if (response.getEntity() != null) {
			ngaResponse.setBody(readResponseBody(response.getEntity().getContent()));
		}
		if (response.getAllHeaders() != null && response.getAllHeaders().length > 0) {
			Map<String, String> mapHeaders = new HashMap<String, String>();
			for (Header header : response.getAllHeaders()) {
				mapHeaders.put(header.getName(), header.getValue());
			}
			ngaResponse.setHeaders(mapHeaders);
		}
		return ngaResponse;
	}

	private String readResponseBody(InputStream is) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int length;
		while ((length = is.read(buffer)) != -1) {
			baos.write(buffer, 0, length);
		}
		return baos.toString(StandardCharsets.UTF_8.toString());
	}

	private NGAResponse login(NGAConfiguration config) {
		HttpResponse response = null;

		try {
			HttpUriRequest loginRequest = buildLoginRequest(config);
			cookieStore.clear();
			response = httpClient.execute(loginRequest);
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				for (Cookie cookie : cookieStore.getCookies()) {
					if (cookie.getName().equals(LWSSO_COOKIE_NAME)) {
						LWSSO_TOKEN = cookie;
					}
					if (cookie.getName().equals(CSRF_COOKIE_NAME)) {
						CSRF_TOKEN = cookie.getValue();
					}
				}
			}
			return createNGAResponse(response);
		} catch (IOException e) {
			logger.error("failed to login to " + config, e);
			throw new RuntimeException("failed to login to " + config, e);
		} finally {
			HttpClientUtils.closeQuietly(response);
		}
	}

	private HttpUriRequest buildLoginRequest(NGAConfiguration config) {
		String authString = (config.getApiKey() != null ? config.getApiKey() : "") + ":" + (config.getSecret() != null ? config.getSecret() : "");
		RequestBuilder requestBuilder = RequestBuilder.post(config.getUrl() + "/" + AUTHENTICATION_URI)
				.setHeader(AUTHENTICATION_HEADER, AUTHENTICATION_BASIC_PREFIX + DatatypeConverter.printBase64Binary(authString.getBytes(StandardCharsets.UTF_8)))
				.setHeader(CLIENT_TYPE_HEADER, CLIENT_TYPE_VALUE);
		return requestBuilder.build();
	}
}
