package com.hpe.application.automation.tools.ssc;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.hpe.application.automation.tools.octane.events.SSCFortifyConfigurations;
//import com.hpe.application.automation.tools.rest.RestClient;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;

/**
 * Created by hijaziy on 7/12/2018.
 */
public class SscConnector {

    CloseableHttpClient httpClient;
    SSCFortifyConfigurations sscFortifyConfigurations;
    String authToken;

    public SscConnector(SSCFortifyConfigurations sscFortifyConfigurations){
        this.sscFortifyConfigurations = sscFortifyConfigurations;
        initConnection();
    }
    public void initConnection() {

        String proxyHost = System.getProperty("http.proxyHost");//"proxy.il.hpecorp.net";
        String proxyPort = System.getProperty("http.proxyPort");
        Integer proxyPortNumber = proxyPort != null ? Integer.valueOf(proxyPort) : null;//8080;


        if (proxyHost != null && !proxyHost.isEmpty() && proxyPortNumber != null) {
            HttpClientBuilder clientBuilder = HttpClients.custom();
            clientBuilder.setProxy(new HttpHost(proxyHost, proxyPortNumber));
            httpClient = clientBuilder.build();
        } else {
            httpClient = HttpClients.createDefault();
        }
        sendReqAuth();
        //sendRequest();
    }

    private void sendReqAuth() {
        //"/{SSC Server Context}/api/v1"
        //String url = "http://" + serverURL + "/ssc/api/v1/projects?q=id:2743&fulltextsearch=true";
        String url = sscFortifyConfigurations.serverURL + "/api/v1/tokens";
        HttpPost request = new HttpPost(url);
        request.addHeader("Authorization",sscFortifyConfigurations.baseToken);
        request.addHeader("Accept", "application/json");
        request.addHeader("Host", getNetHost(sscFortifyConfigurations.serverURL));
        request.addHeader("Content-Type","application/json;charset=UTF-8");

        String body = "{\"type\": \"UnifiedLoginToken\"}";
        CloseableHttpResponse response = null;
        try {
            HttpEntity entity = new ByteArrayEntity(body.getBytes("UTF-8"));
            request.setEntity(entity);
            response = httpClient.execute(request);
            if(succeeded(response.getStatusLine().getStatusCode())) {

                String toString = isToString(response.getEntity().getContent());
                AuthToken authToken = new ObjectMapper().readValue(toString,
                        TypeFactory.defaultInstance().constructType(AuthToken.class));
                this.authToken = authToken.data.token;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }catch (Exception e){
        }
        finally {
            if(response != null){
                EntityUtils.consumeQuietly(response.getEntity());
                HttpClientUtils.closeQuietly(response);
            }
        }

    }

    private String getNetHost(String serverURL) {
        //http://myd-vma00564.swinfra.net:8180/ssc
        String prefix = "http://";
        int indexOfStart = serverURL.toLowerCase().indexOf(prefix) + prefix.length();
        int indexOfEnd = serverURL.lastIndexOf("/");
        if(indexOfEnd < 0){
            return serverURL.substring(indexOfStart);
        }
        return serverURL.substring(indexOfStart,indexOfEnd);
    }

    private boolean succeeded(int statusCode) {
        return statusCode == 200 || statusCode == 201;
    }


    private String sendGetEntity(String urlSuffix) {
        String url = sscFortifyConfigurations.serverURL + "/api/v1/" + urlSuffix;
        return sendGetRequest(url);
    }
    private String sendGetRequest(String url) {

        HttpGet request = new HttpGet(url);

        //request.addHeader("Authorization","FortifyToken ODBjMmI0ODEtOTNiMC00Mzc3LWFlOGEtM2JhNzFjYjA3NTZi");
        request.addHeader("Authorization","FortifyToken " + this.authToken);
        request.addHeader("Accept", "application/json");
        request.addHeader("Host", getNetHost(sscFortifyConfigurations.serverURL));

        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(request);
            String toString = isToString(response.getEntity().getContent());
            return toString;
        } catch (IOException e) {
            e.printStackTrace();
        }catch (Exception e){

        }
        finally {
            if(response != null){
                EntityUtils.consumeQuietly(response.getEntity());
                HttpClientUtils.closeQuietly(response);
            }
        }
        return null;
    }

    static String isToString(InputStream is) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString();
    }

    public ProjectVersions.ProjectVersion getProjectVersion() {
        Integer projectId = getProjectId();
        if(projectId == null){
            return null;
        }
        String suffix = "projects/" + projectId + "/versions?q=name:" + this.sscFortifyConfigurations.projectVersion;
        String rawResponse = sendGetEntity(suffix);
        ProjectVersions projectVersions = responseToObject(rawResponse, ProjectVersions.class);
        if(projectVersions.data.length == 0){
            return null;
        }
        return projectVersions.data[0];
    }

    public Integer getProjectId(){
        String rawResponse = sendGetEntity("projects?q=name:" + this.sscFortifyConfigurations.projectName);
        Projects projects = responseToObject(rawResponse, Projects.class);
        if(projects.data.length == 0){
            return null;
        }
        return projects.data[0].id;
    }

    public <T> T responseToObject(String response, Class<T> type) {
        if(response == null){
            return null;
        }
        try {
            return new ObjectMapper().readValue(response,
                    TypeFactory.defaultInstance().constructType(type));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }




    public static void main(String[] args){
        SSCFortifyConfigurations sscFortifyConfigurations = new SSCFortifyConfigurations();
        sscFortifyConfigurations.baseToken = "Basic QWRtaW46ZGV2c2Vjb3BzMQ==";//ConfigurationService.getServerConfiguration().getSscBaseToken(); //"Basic QWRtaW46ZGV2c2Vjb3Bz";
        sscFortifyConfigurations.projectName = "YaminApp";
        sscFortifyConfigurations.projectVersion = "1";
        sscFortifyConfigurations.serverURL = "myd-vma00564.swinfra.net:8180"; //http://myd-vma00564.swinfra.net:8180/ssc
        SscConnector sscConnector = new SscConnector(sscFortifyConfigurations);

    }

    public Issues readIssuesOfLastestScan(ProjectVersions.ProjectVersion projectVersion) {
        String urlSuffix = String.format("projectVersions/%d/issues", projectVersion.currentState.id);
        String rawResponse = sendGetEntity(urlSuffix);
        return responseToObject(rawResponse, Issues.class);
    }
}
