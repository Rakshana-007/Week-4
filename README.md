# Week-4

package com.rakshanamart.servlet;

import com.rakshanamart.util.DBConnection;
import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

@WebServlet("/register")
public class RegisterServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        request.setCharacterEncoding("UTF-8");

        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        if (name == null || email == null || password == null ||
            name.isBlank() || email.isBlank() || password.length() < 8) {
            response.sendError(400,
                    "Enter your name, email, and a password of at least 8 characters.");
            return;
        }

        String hashedPassword =
                BCrypt.hashpw(password, BCrypt.gensalt(12));

        String sql = "INSERT INTO customers (name, email, password) VALUES (?, ?, ?)";

        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, name.trim());
            ps.setString(2, email.trim().toLowerCase());
            ps.setString(3, hashedPassword);

            ps.executeUpdate();
            response.sendRedirect("login.html?registered=true");

        } catch (SQLException e) {
            getServletContext().log("Registration failed", e);

            if ("23000".equals(e.getSQLState())) {
                response.sendError(409, "Email may already be registered.");
            } else {
                response.sendError(500, "Registration failed.");
            }
        }
    }
}
