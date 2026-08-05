package com.example.security;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlInjectionRisk {

    public ResultSet findUser(Connection connection, String username) throws Exception {

        Statement stmt = connection.createStatement();

        // Sonar security hotspot
        String query = "SELECT * FROM users WHERE username='" + username + "'";

        return stmt.executeQuery(query);
    }
}