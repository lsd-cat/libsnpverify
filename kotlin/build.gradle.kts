plugins {
    kotlin("jvm") version "2.4.0"
    `java-library`
    `maven-publish`
    id("org.jlleitschuh.gradle.ktlint") version "13.0.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
}

group = "sh.lsd"
version = "0.1.0"

repositories { mavenCentral() }

// Built with JDK 21, emitted for JVM 11 so the artifact runs on Android (API 26+: java.time, java.util.Base64) and server JVMs.
kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11);
        freeCompilerArgs.add("-Xjdk-release=11")
    }
}
java {
    sourceCompatibility = JavaVersion.VERSION_11;
    targetCompatibility = JavaVersion.VERSION_11;
    withSourcesJar()
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(files("detekt.yml"))
    source.setFrom("src/main/kotlin")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "libsnpverify-kt"
            pom {
                licenses {
                    license {
                        name.set("GPL-3.0-or-later")
                        url.set("https://www.gnu.org/licenses/gpl-3.0.txt")
                    }
                }
            }
        }
    }
}

dependencies {
    // Main: zero dependencies. JCA only.
    testImplementation(kotlin("test"))
    testImplementation("com.google.code.gson:gson:2.11.0")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78.1") // exercises the pluggable provider path
}

tasks.test {
    useJUnitPlatform()
    systemProperty("vectors.dir", rootProject.projectDir.resolve("../vectors").canonicalPath)
    testLogging {
        events("failed");
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
