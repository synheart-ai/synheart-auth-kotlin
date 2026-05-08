plugins {
    kotlin("jvm") version "2.1.10" apply false
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

group = (findProperty("GROUP") ?: "ai.synheart").toString()
version = (findProperty("VERSION_NAME") ?: "0.1.0").toString()

allprojects {
    repositories {
        mavenCentral()
    }
}

nexusPublishing {
    repositories {
        sonatype {
            // OSSRH was shut down (2025-06-30). Use the Central Portal OSSRH Staging API compatibility service.
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))

            username.set(
                (findProperty("sonatypeUsername")
                    ?: findProperty("SONATYPE_USERNAME")
                    ?: System.getenv("SONATYPE_USERNAME")
                    ?: "").toString()
            )
            password.set(
                (findProperty("sonatypePassword")
                    ?: findProperty("SONATYPE_PASSWORD")
                    ?: System.getenv("SONATYPE_PASSWORD")
                    ?: "").toString()
            )
        }
    }
}
