/*
 * Copyright 2020 momosecurity.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.immomo.momosec.maven.plugins;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.testing.MojoRule;
import org.apache.maven.plugin.testing.resources.TestResources;
import org.eclipse.aether.DefaultSessionData;
import org.eclipse.aether.RepositorySystemSession;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;

import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.*;


@RunWith(PowerMockRunner.class)
@PrepareForTest(value = {HttpClientHelper.class, MosecTestMojo.class})
@PowerMockIgnore({
        "com.sun.org.apache.xerces.*",
        "javax.xml.*",
        "org.xml.*",
        "org.w3c.*",
        "javax.management.*"
})
public class TestMosecTestMojo {

    @Rule
    public MojoRule rule = new MojoRule();

    @Rule
    public TestResources resources = new TestResources("src/test/resources/projects", "target/test-projects");

    @Rule
    @SuppressWarnings(value = {"deprecation"})
    public ExpectedException exceptionRule = ExpectedException.none();

    private final ArrayList<String> parameters = new ArrayList<String>(){{
        add("severity");
        add("transitive");
        add("scope");
        add("failOnVuln");
        add("endpoint");
        add("output");
        add("onlyAnalyze");
        add("skip");
    }};

    @Test
    public void invalidProjectTest() throws Exception {
        File projectCopy = this.resources.getBasedir("empty-dir");
        File pom = new File(projectCopy, "pom.xml");

        exceptionRule.expect(java.io.FileNotFoundException.class);
        exceptionRule.expectMessage("(No such file or directory)");

        this.rule.lookupMojo("test", pom.getCanonicalPath());
    }

    @Test
    public void validProjectTest() throws Exception {
        File pom = getPom("valid-project", "pom.xml");

        MosecTestMojo mosecTestMojo = (MosecTestMojo)this.rule.lookupMojo("test", pom);
        Assert.assertNotNull(mosecTestMojo);
    }

    private MosecTestMojo getMockMosecTest(File pom) throws Exception {
        MosecTestMojo mosecTestMojo = spy((MosecTestMojo) this.rule.lookupMojo("test", pom));

        RepositorySystemSession mockRepositorySystemSession = mock(RepositorySystemSession.class);

        when(mosecTestMojo.getLog()).thenReturn(mock(Log.class));
        when(mockRepositorySystemSession.getData()).thenReturn(new DefaultSessionData());
        when(mosecTestMojo, "isAnalyzeTotalFinished", any()).thenReturn(false);

        Field repoSystemSession = mosecTestMojo.getClass().getDeclaredField("repositorySystemSession");
        repoSystemSession.setAccessible(true);
        repoSystemSession.set(mosecTestMojo, mockRepositorySystemSession);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(pom);
        NodeList configurationNodeList = document.getElementsByTagName("configuration");
        Node configurationNode;
        NodeList configurationChilds;
        if (configurationNodeList.getLength() > 0) {
            configurationNode = configurationNodeList.item(0);
            configurationChilds = configurationNode.getChildNodes();
            int length = configurationChilds.getLength();
            for (int i = 0; i < length; i++) {
                Node configItem = configurationChilds.item(i);
                if (!(configItem instanceof Element)) {
                    continue;
                }
                String name = configItem.getNodeName();
                if (!parameters.contains(name)) {
                    continue;
                }
                String value = configItem.getTextContent();

                if (value != null) {
                    Field field = mosecTestMojo.getClass().getDeclaredField(name);
                    field.setAccessible(true);
                    if (field.getType() == String.class) {
                        field.set(mosecTestMojo, value);
                    } else if (field.getType() == Boolean.class) {
                        field.set(mosecTestMojo, Boolean.parseBoolean(value));
                    }
                }
            }
        }

        return mosecTestMojo;
    }

    @Test
    public void onlyAnalyzeWithoutEndpointPom() throws Exception {
        File pom = getPom("valid-project", "onlyAnalyzeWithoutEndpointPom.xml");
        MosecTestMojo mosecTestMojo = getMockMosecTest(pom);
        mosecTestMojo.execute();
    }

    @Test
    public void onlyAnalyzeWithEndpointPom() throws Exception {
        File pom = getPom("valid-project", "onlyAnalyzeWithEndpointPom.xml");
        MosecTestMojo mosecTestMojo = getMockMosecTest(pom);
        mosecTestMojo.execute();
    }

    @Test
    public void testFailOnVulnWithTruePom() throws Exception {
        File pom = getPom("valid-project", "failOnVulnWithTruePom.xml");
        exceptionRule.expectMessage("Dependency Vulnerable Found!");
        failOnVulnPomRunner(pom);
    }

    @Test
    public void testFailOnVulnWithFalsePom() throws Exception {
        File pom = getPom("valid-project", "failOnVulnWithFalsePom.xml");
        failOnVulnPomRunner(pom);
    }

    private void failOnVulnPomRunner(File pom) throws Exception {
        MosecTestMojo mosecTestMojo = getMockMosecTest(pom);

        HttpClientHelper mockHttpClientHelper = mock(HttpClientHelper.class);
        HttpClient mockHttpClient = mock(HttpClient.class);
        HttpResponse mockHttpResponse = mock(HttpResponse.class);
        StatusLine mockStatusLine = mock(StatusLine.class);
        HttpEntity mockHttpEntity = mock(HttpEntity.class);

        whenNew(HttpClientHelper.class).withAnyArguments().thenReturn(mockHttpClientHelper);
        when(mockHttpClientHelper.buildHttpClient()).thenReturn(mockHttpClient);
        when(mockHttpClient.execute(any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mosecTestMojo, "isAnalyzeTotalFinished", any()).thenReturn(false);
        String vuln = "{\"ok\":false, \"dependencyCount\": 2, \"vulnerabilities\":[{" +
                "\"severity\": \"High\"," +
                "\"title\": \"Fastjson RCE\"," +
                "\"cve\": \"CVE-0000-0001\"," +
                "\"packageName\": \"com.alibaba:fastjson\"," +
                "\"version\": \"1.2.33\"," +
                "\"target_version\": [\"1.2.80\"]" +
                "}]}";
        InputStream httpResponseContent = new ByteArrayInputStream(vuln.getBytes());
        when(mockHttpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(mockHttpEntity.getContent()).thenReturn(httpResponseContent);

        mosecTestMojo.execute();
    }

    public File getPom(String baseDir, String fn) throws IOException {
        File projectCopy = this.resources.getBasedir(baseDir);
        File pom = new File(projectCopy, fn);

        Assert.assertNotNull(pom);
        Assert.assertTrue(pom.exists());

        return pom;
    }

}
