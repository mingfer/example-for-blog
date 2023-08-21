package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static java.util.Objects.isNull;

public class Main {
    public static void main(String[] args) {
        System.out.println(version());
    }

    public static String version() {
        Properties properties = new Properties();
        try (InputStream stream = Main.class.getClassLoader().getResourceAsStream("git.properties")) {
            if (isNull(stream)) {
                throw new IllegalStateException("git.properties file not found in jar");
            }
            properties.load(stream);
            String version = properties.getProperty("git.build.version");
            String commitID = properties.getProperty("git.commit.id.abbrev");
            String time = properties.getProperty("git.build.time");
            return "Maven Git Commit ID Example V" + version + "(" + commitID + ") was built on " + time;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}