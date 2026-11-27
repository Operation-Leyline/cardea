plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.jvm) apply false
}

// Both artifacts share a group, a version and the same repositories to publish to.
subprojects {
    group = providers.gradleProperty("cardea.group").get()
    version = providers.gradleProperty("cardea.version").get()

    pluginManager.withPlugin("maven-publish") {
        extensions.configure<PublishingExtension> {
            repositories {
                // `./gradlew publish` writes here; `-Pcardea.publishDir=…` moves it.
                maven {
                    name = "Directory"
                    url = uri(
                        providers.gradleProperty("cardea.publishDir").orNull
                            ?: rootProject.layout.buildDirectory.dir("repo").get().asFile,
                    )
                }
            }
            publications.withType<MavenPublication>().configureEach {
                pom {
                    name.set(project.name)
                    description.set(provider { project.description })
                    url.set("https://github.com/Operation-Leyline/cardea")
                    licenses {
                        license {
                            name.set("Apache-2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    scm {
                        url.set("https://github.com/Operation-Leyline/cardea")
                        connection.set("scm:git:https://github.com/Operation-Leyline/cardea.git")
                    }
                }
            }
        }
    }
}
