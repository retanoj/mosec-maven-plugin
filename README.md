# MOSEC-MAVEN-PLUGIN

用于检测maven项目的第三方依赖组件是否存在安全漏洞。


v1.0.0版本基于eclipse-aether，对依赖解析存在诸多问题。
v2.0.0版改用Maven Mojo `requiresDependencyCollection` 做依赖解析，插件只做依赖提取与分析。


## 版本要求

Maven >= 3.2



## 安装

#### 向pom.xml中添加plugin仓库 (项目级安装)

```xml
<!-- pom.xml -->

<pluginRepositories>
  <pluginRepository>
      <id>gh</id>
      <url>https://raw.githubusercontent.com/retanoj/mosec-maven-plugin/master/mvn-repo/</url>
  </pluginRepository>
</pluginRepositories>
```

#### 向maven配置中添加plugin仓库 (全局安装)

```xml
<!-- settings.xml -->

<!-- 添加pluginGroup可简化命令行参数 -->
<pluginGroups>
    <pluginGroup>com.immomo.momosec</pluginGroup>
</pluginGroups>

<profiles>
    <profile>
      <id>momo-plugin</id>
      <pluginRepositories>
        <pluginRepository>
            <id>gh</id>
            <url>https://raw.githubusercontent.com/retanoj/mosec-maven-plugin/master/mvn-repo/</url>
        </pluginRepository>
      </pluginRepositories>
    </profile>
</profiles>

<activeProfiles>
    <activeProfile>momo-plugin</activeProfile>
</activeProfiles>
```




## 使用


#### 命令行使用
```
> cd your_maven_project_dir/

> MOSEC_ENDPOINT=http://127.0.0.1:9000/api/plugin \
  mvn com.immomo.momosec:mosec-maven-plugin:2.0.0:test \
  -Dseverity=High

// 或简化方式

> MOSEC_ENDPOINT=http://127.0.0.1:9000/api/plugin \
  mvn mosec:test -Dseverity=High
```

#### 项目中使用

```xml
<!-- pom.xml -->

<plugins>
    <plugin>
        <groupId>com.immomo.momosec</groupId>
        <artifactId>mosec-maven-plugin</artifactId>
        <version>2.0.0</version>
        <executions>
            <execution>
                <id>test</id>
                <goals>
                    <goal>test</goal>  <!-- test过程执行 -->
                </goals>
            </execution>
        </executions>
        <configuration>
            <endpoint>http://127.0.0.1:9000/api/plugin</endpoint>
            <severityLevel>High</severityLevel>
            <failOnVuln>true</failOnVuln>
        </configuration>
    </plugin>
</plugins>
```



## 帮助

```shell script
> mvn mosec:help -Ddetail=true

mosec:resolve
  收集依赖，解析POM文件，并解析依赖 此goal会下载jar包

mosec:test
  收集依赖，解析POM文件
  
  Available parameters:

    severity (Default: High)
      威胁等级 [High|Medium|Low]
      User property: severity
    
    transitive (Default: true)
      检查传递依赖
      User property: transitive     
    
    scope (Default: "")
      依赖按scope过滤，逗号分割 [runtime|compile|provided|system|test]
      User property: scope
           
    failOnVuln (Default: true)
      发现漏洞即编译失败
      User property: failOnVuln
    
    endpoint
      上报API
      User property: endpoint

    output (Default: )
      输出依赖树到文件
      User property: output

    onlyAnalyze (Default: false)
      仅分析不上报
      User property: onlyAnalyze

    mosec.skip (Default: false)
      跳过插件执行
      User property: mosec.skip

```


## 开发

#### Intellij 远程调试 Maven 插件

1.将mosec-maven-plugin拉取至本地仓库

2.git clone mosec-maven-plugin 源码

3.Intellij 打开mosec-maven-plugin项目，新建 Remote Configuration 并填入如下信息

![remote-configuration](./static/remote-configuration.jpg)

4.在另一个maven工程中执行如下命令

```shell script
> mvnDebug com.immomo.momosec:mosec-maven-plugin:2.0.0:test
```

5.回到Intellij中，下断点，开始Debug
