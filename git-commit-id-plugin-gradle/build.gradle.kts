plugins {
    id("java")
    id("com.gorylenko.gradle-git-properties") version "2.4.1"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}


tasks.jar {
    manifest {
        attributes["Main-Class"] = "org.example.Main"
    }
}

tasks.test {
    useJUnitPlatform()
}
