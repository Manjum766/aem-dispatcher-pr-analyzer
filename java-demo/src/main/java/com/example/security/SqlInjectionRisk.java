package com.example.security;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SqlInjectionRisk {

    // Use PreparedStatement with parameter binding — never concatenate user input into SQL
    public ResultSet findUser(Connection connection, String username) throws SQLException {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM users WHERE username = ?");
        ps.setString(1, username);
        return ps.executeQuery();
    }
}
