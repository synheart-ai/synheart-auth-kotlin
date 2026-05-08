import java.util.Base64

plugins {
    kotlin("jvm")
    `maven-publish`
    signing
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

group = (findProperty("GROUP") ?: "ai.synheart").toString()
version = (findProperty("VERSION_NAME") ?: "0.1.0").toString()
val pomArtifactId = (findProperty("POM_ARTIFACT_ID") ?: "synheart-auth").toString()

dependencies {
    implementation("org.json:json:20231013")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["java"])

            groupId = project.group.toString()
            artifactId = pomArtifactId
            version = project.version.toString()

            pom {
                name.set("Synheart Auth (Kotlin)")
                description.set("Synheart device authentication SDK for Kotlin/JVM. Hardware-backed request signing, attestation, and device registration. Platform backends (Android Keystore, iOS Secure Enclave) are wired via pluggable providers.")
                url.set("https://github.com/synheart-ai/synheart-auth-kotlin")

                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }

                developers {
                    developer {
                        id.set("israel-goytom")
                        name.set("Israel Goytom")
                        email.set("israel@synheart.ai")
                    }
                    developer {
                        id.set("synheart-ai")
                        name.set("Synheart AI Team")
                        email.set("dev@synheart.ai")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/synheart-ai/synheart-auth-kotlin.git")
                    developerConnection.set("scm:git:ssh://github.com/synheart-ai/synheart-auth-kotlin.git")
                    url.set("https://github.com/synheart-ai/synheart-auth-kotlin")
                }
            }
        }
    }
}

signing {
    // Support both `GPG_*` and `SIGNING_*` naming (CI commonly uses ORG_GRADLE_PROJECT_SIGNING_*).
    var signingKey = (findProperty("GPG_PRIVATE_KEY")
        ?: findProperty("SIGNING_KEY")
        ?: System.getenv("GPG_PRIVATE_KEY")
        ?: System.getenv("SIGNING_KEY")
        ?: "").toString()
    val signingKeyBase64 = (findProperty("GPG_PRIVATE_KEY_BASE64")
        ?: findProperty("SIGNING_KEY_BASE64")
        ?: System.getenv("GPG_PRIVATE_KEY_BASE64")
        ?: System.getenv("SIGNING_KEY_BASE64")
        ?: "").toString()
    val signingPassword = (findProperty("GPG_PASSPHRASE")
        ?: findProperty("SIGNING_PASSWORD")
        ?: System.getenv("GPG_PASSPHRASE")
        ?: System.getenv("SIGNING_PASSWORD")
        ?: "").toString()

    // Prefer base64 when provided (robust for CI / dotenv / shells).
    if (signingKeyBase64.isNotBlank()) {
        val normalized = signingKeyBase64.replace(Regex("\\s+"), "")
        signingKey = String(Base64.getMimeDecoder().decode(normalized), Charsets.UTF_8)
    }

    // Support `.env`-style single-line values with escaped newlines.
    signingKey = signingKey
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\\n", "\n")
        .trim()

    val hasSigning = signingKey.isNotBlank() && signingPassword.isNotBlank()

    if (hasSigning) {
        useInMemoryPgpKeys(signingKey, signingPassword)
    }

    // Don't require signing for local `publishToMavenLocal` tests.
    // Require signing when publishing to Sonatype (Maven Central requirement).
    isRequired = hasSigning && gradle.taskGraph.allTasks.any { t ->
        val n = t.name.lowercase()
        n.contains("sonatype") || n.contains("close") || n.contains("release")
    }
    sign(publishing.publications["release"])
}
