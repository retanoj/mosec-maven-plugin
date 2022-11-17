package com.immomo.momosec.maven.plugins;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * 收集依赖，解析POM文件，并解析依赖
 * 此goal会下载jar包
 */
@Mojo(name = "resolve",
        requiresDependencyCollection = ResolutionScope.TEST,
        requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.GENERATE_SOURCES,
        threadSafe = true )
public class MosecResolveMojo extends MosecTestMojo {
    // resolve dependency jar but not only pom
}
