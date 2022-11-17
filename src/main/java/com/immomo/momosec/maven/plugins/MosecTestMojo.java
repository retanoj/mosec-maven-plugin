package com.immomo.momosec.maven.plugins;

import com.google.gson.*;
import com.immomo.momosec.maven.plugins.exceptions.NetworkErrorException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Settings;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.SessionData;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.TreeSet;

import static com.immomo.momosec.maven.plugins.Renderer.writeToFile;

/**
 * 收集依赖，解析POM文件
 */
@Mojo(name = "test",
        requiresDependencyCollection = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.GENERATE_SOURCES,
        threadSafe = true )
public class MosecTestMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repositorySystemSession;

    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private Settings settings;

    /**
     * 威胁等级 [High|Medium|Low]
     */
    @Parameter(property = "severity", defaultValue = "High")
    private String severity;

    /**
     * 检查传递依赖
     */
    @Parameter(property = "transitive", defaultValue = "true")
    private Boolean transitive;

    /**
     * 依赖按scope过滤，逗号分割 [runtime|compile|provided|system|test]
     */
    @Parameter(property = "scope", defaultValue = "")
    private String scope;

    /**
     * 发现漏洞即编译失败
     */
    @Parameter(property = "failOnVuln", defaultValue = "true")
    private Boolean failOnVuln;

    /**
     * 上报API
     */
    @Parameter(property = "endpoint")
    private String endpoint;

    /**
     * 输出依赖树到文件
     */
    @Parameter(property = "output", defaultValue = "")
    private String output;

    /**
     * 仅分析依赖，不进行漏洞检查
     */
    @Parameter(property = "onlyAnalyze", defaultValue = "false")
    private Boolean onlyAnalyze;

    /**
     * 跳过插件执行
     */
    @Parameter(property = "mosec.skip", defaultValue = "false")
    private boolean skip;

    private static List<String> totalProjectsByGAV = null;

    @SuppressWarnings(value = {"unchecked"})
    public void execute() throws MojoFailureException {
        if (skip) {
            getLog().info( "Skipping Mosec plugin execution." );
            return;
        }

        String env_endpoint = System.getenv(Constants.MOSEC_ENDPOINT_ENV);
        if (env_endpoint != null) {
            endpoint = env_endpoint;
        }

        if (Boolean.FALSE.equals(onlyAnalyze) && endpoint == null) {
            throw new MojoFailureException(Constants.ERROR_ON_NULL_ENDPOINT);
        }

        try {
            SessionData sessionData = repositorySystemSession.getData();
            if (sessionData.get("collectTree") == null) {
                sessionData.set("collectTree", new ArrayList<String>());
            }
            if (sessionData.get("collectGAV") == null) {
                sessionData.set("collectGAV", new ArrayList<String>());
            }

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            List<String> collectTree = (ArrayList<String>) sessionData.get("collectTree");
            List<String> collectGAV = (ArrayList<String>) sessionData.get("collectGAV");

            ProjectDependencyCollector collector = new ProjectDependencyCollector(
                    project,
                    getLog(),
                    scope,
                    transitive
            );
            collector.collectDependencies();
            JsonObject projectTree = collector.getTree();
            String jsonProjectTree = gson.toJson(projectTree);
            getLog().debug(jsonProjectTree);

            collectTree.add(jsonProjectTree);
            collectGAV.add(String.format("%s:%s",
                    projectTree.get("name").getAsString(), projectTree.get("version").getAsString()));
            if (Boolean.TRUE.equals(onlyAnalyze)) {
                if (this.isAnalyzeTotalFinished(collectGAV)
                        && output != null
                        && !"".equals(output)
                ) {
                    writeToFile(output, collectTree);
                }

                getLog().info("onlyAnalyze mode, Done.");
                return;
            }

            projectTree.addProperty("type", Constants.BUILD_TOOL_TYPE);
            projectTree.addProperty("language", Constants.PROJECT_LANGUAGE);
            projectTree.addProperty("severity", severity);

            HttpPost request = new HttpPost(endpoint);
            request.addHeader("content-type", Constants.CONTENT_TYPE_JSON);
            HttpEntity entity = new StringEntity(projectTree.toString());
            request.setEntity(entity);

            HttpClientHelper httpClientHelper = new HttpClientHelper(getLog(), settings);
            HttpClient client = httpClientHelper.buildHttpClient();
            HttpResponse response = client.execute(request);

            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new NetworkErrorException(response.getStatusLine().getReasonPhrase());
            }

            JsonObject responseJson;
            try {
                responseJson = JsonParser.parseReader(
                        new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
                ).getAsJsonObject();
                JsonObject lastTree = (JsonObject) JsonParser.parseString(collectTree.get(collectTree.size() - 1));
                lastTree.add("result", responseJson);
                collectTree.set(collectTree.size() - 1, gson.toJson(lastTree));
            } catch (JsonParseException | IllegalStateException e) {
                throw new NetworkErrorException(Constants.ERROR_ON_API);
            }

            if (output != null && !"".equals(output)) {
                writeToFile(output, collectTree);
            }

            Renderer renderer = new Renderer(getLog(), failOnVuln);
            renderer.renderResponse(responseJson);

        } catch (MojoFailureException e) {
            throw e;
        } catch (Exception e) {
            if (getLog().isDebugEnabled()) {
                getLog().error(Constants.ERROR_GENERAL, e);
            } else {
                getLog().error(Constants.ERROR_GENERAL);
                getLog().error(Constants.ERROR_RERUN_WITH_DEBUG);
            }
            throw new MojoFailureException(e.getMessage(), e.fillInStackTrace());
        }
    }

    @SuppressWarnings("unchecked")
    private boolean isAnalyzeTotalFinished(List<String> analyzedProjectsByGAV) {
        if (totalProjectsByGAV == null) {
            Object key = repositorySystemSession.getWorkspaceReader().getRepository().getKey();
            if (key instanceof HashSet) {
                totalProjectsByGAV = new ArrayList<>((HashSet<String>) key);
            } else {
                return false;
            }
        }

        if (analyzedProjectsByGAV == null || totalProjectsByGAV.size() != analyzedProjectsByGAV.size()) {
            return false;
        }
        return new TreeSet<>(totalProjectsByGAV).equals(new TreeSet<>(analyzedProjectsByGAV));
    }
}
