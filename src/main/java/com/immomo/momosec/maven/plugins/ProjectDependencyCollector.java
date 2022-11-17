/*
 * Copyright 2017 Snyk Ltd.
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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

import java.util.*;

public class ProjectDependencyCollector {

    private final MavenProject project;
    private final List<String> scope;
    private final boolean transitive;

    private JsonObject tree;

    private final Log log;

    public ProjectDependencyCollector(MavenProject project, Log log, String scope, boolean transitive) {
        this.project = project;
        this.log = log;
        this.scope = scope == null ? Collections.emptyList() : Arrays.asList(scope.split(","));
        this.transitive = transitive;
    }

    public void collectDependencies() {
        tree = createTreeNode(project.getArtifact());

        project.getArtifacts().forEach(this::addArtifactToTree);

        MavenProject parentProject = this.project.getParent();
        if (parentProject == null) {
            this.tree.add("parent", new JsonObject());
        } else {
            Artifact parent = parentProject.getArtifact();
            JsonObject jParent = createTreeNode(parent);
            jParent.remove("from");
            jParent.remove("dependencies");
            this.tree.add("parent", jParent);
        }

        tree.add("modules", (new Gson()).toJsonTree(project.getModules()).getAsJsonArray());
    }

    private void addArtifactToTree(Artifact artifact) {
        if (!transitive &&
                artifact.getDependencyTrail() != null &&
                artifact.getDependencyTrail().size() > 2
        ) {
            getLog().debug(String.format("ignore %s:%s:%s",
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion()));
            return ;
        }

        if (!"".equals(artifact.getScope()) &&
                !scope.isEmpty() &&
                !scope.contains(artifact.getScope())
        ) {
            getLog().debug(String.format("ignore %s:%s:%s",
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion()));
            return ;
        }

        JsonObject node = createTreeNode(artifact);
        JsonObject ancestor = tree;

        List<String> artifactTrails = artifact.getDependencyTrail();
        int trailsLength = artifactTrails.size();

        // jump idx = 0
        for (int idx = 1; idx < trailsLength; idx ++) {
            String trailGATV = artifactTrails.get(idx);

            boolean findAncestor = false;
            JsonObject dependencies = ancestor.getAsJsonObject("dependencies");
            for (Map.Entry<String, JsonElement> entry : dependencies.entrySet()) {
                JsonObject dependency = entry.getValue().getAsJsonObject();
                if (getGATV(dependency).equals(trailGATV)) {
                    ancestor = dependency;
                    findAncestor = true;
                    break;
                }
            }

            // dangling dependency
            if (!findAncestor && idx != trailsLength - 1) {
                getLog().error(String.format("ignore dangling dependency %s:%s:%s",
                        artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion()));
                return ;
            }
        }

        JsonObject dependencies = ancestor.getAsJsonObject("dependencies");
        dependencies.add(node.get("name").getAsString(), node);
    }

    private JsonObject createTreeNode(Artifact artifact) {
        JsonObject treeNode = new JsonObject();

        treeNode.addProperty("name", String.format("%s:%s", artifact.getGroupId(), artifact.getArtifactId()));

        treeNode.addProperty("version", artifact.getBaseVersion());

        treeNode.addProperty("type", artifact.getType());

        String scope = artifact.getScope();
        treeNode.addProperty("scope", scope == null ? "compile" : scope);


        treeNode.addProperty("gatvs", scope == null ?
                String.format("%s:%s", artifact.toString(), "compile") : artifact.toString());

        List<String> trails = artifact.getDependencyTrail();
        if (trails == null) {
            trails = new ArrayList<>();
        }
        treeNode.add("from", new Gson().toJsonTree(trails).getAsJsonArray());

        treeNode.add("dependencies", new JsonObject());

        return treeNode;
    }

    private String getGATV(JsonObject node) {
        return String.format("%s:%s:%s",
                node.get("name").getAsString(),
                node.get("type").getAsString(),
                node.get("version").getAsString());
    }

    public JsonObject getTree() { return this.tree; }

    private Log getLog() {
        return log;
    }
}
