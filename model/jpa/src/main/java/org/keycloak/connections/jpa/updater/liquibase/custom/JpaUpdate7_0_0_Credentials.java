package org.keycloak.connections.jpa.updater.liquibase.custom;

import liquibase.exception.CustomChangeException;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Table;
import org.keycloak.common.util.Base64;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class JpaUpdate7_0_0_Credentials extends CustomKeycloakTask {

    @Override
    protected void generateStatementsImpl() throws CustomChangeException {

        Map<String, List<String>> userCredentialLists = new HashMap<>();

        String credentialTableName = database.correctObjectName("CREDENTIAL", Table.class);
        try (PreparedStatement statement = jdbcConnection.prepareStatement("SELECT ID, USER_ID, HASH_ITERATIONS, SALT, TYPE, VALUE, COUNTER, DIGITS, PERIOD, ALGORITHM FROM " + credentialTableName);
             ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                String id = rs.getString("ID").trim();
                String userId = rs.getString("USER_ID").trim();
                String hashIterations = rs.getString("HASH_ITERATIONS").trim();
                if (rs.wasNull()) {
                    hashIterations = "";
                }
                byte[] salt = rs.getBytes("SALT");
                if (rs.wasNull()) {
                    salt = new byte[0];
                }
                String type = rs.getString("TYPE").trim();
                if (rs.wasNull()) {
                    type = "";
                }
                String value = rs.getString("VALUE").trim();
                if (rs.wasNull()) {
                    value = "";
                }
                String counter = rs.getString("COUNTER").trim();
                if (rs.wasNull()) {
                    counter = "";
                }
                String digits = rs.getString("DIGITS").trim();
                if (rs.wasNull()) {
                    digits = "";
                }
                String period = rs.getString("PERIOD").trim();
                if (rs.wasNull()) {
                    period = "";
                }
                String algorithm = rs.getString("ALGORITHM").trim();
                if (rs.wasNull()) {
                    algorithm = "";
                }
                //transform credential
                switch (type) {
                    case "password":
                    case "password-history":
                        statements.add(
                                new UpdateStatement(null, null, credentialTableName)
                                        .addNewColumnValue("SECRET_DATA", "{\"value\":\"" + value + "\",\"salt\":\"" + Base64.encodeBytes(salt) + "\"}")
                                        .addNewColumnValue("CREDENTIAL_DATA", "{\"hashIterations\":" + hashIterations + ",\"algorithm\":\"" + algorithm + "\"}")
                                        .setWhereClause("ID = '" + id + "'")
                        );
                        break;
                    case "hotp":
                    case "totp":
                        statements.add(
                                new UpdateStatement(null, null, credentialTableName)
                                        .addNewColumnValue("SECRET_DATA", "{\"value\":\"" + value + "\"}")
                                        .addNewColumnValue("CREDENTIAL_DATA", "{\"subType\":\"" + type + "\",\"digits\":" + digits
                                                + ",\"counter\":" + counter + ",\"period\":" + period + ",\"algorithm\":\"" + algorithm + "\"}")
                                        .addNewColumnValue("TYPE", OTPCredentialModel.TYPE)
                                        .setWhereClause("ID = '" + id + "'")
                        );
                }

                //add credential to user's list
                if (!userCredentialLists.containsKey(userId)){
                    userCredentialLists.put(userId, new ArrayList<>());
                }
                userCredentialLists.get(userId).add(id);
            }

            //for each user, create linkedlist from their credentials
            for (Map.Entry<String, List<String>> entry :userCredentialLists.entrySet()) {
                String previousId = null;
                for (String credentialId : entry.getValue()) {
                    statements.add(
                            new UpdateStatement(null, null, credentialTableName)
                                    .addNewColumnValue("PREVIOUS_CREDENTIAL_LINK", previousId)
                                    .setWhereClause("ID='"+ credentialId + "'"));
                    if (previousId != null){
                        statements.add(
                                new UpdateStatement(null, null, credentialTableName)
                                        .addNewColumnValue("NEXT_CREDENTIAL_LINK", credentialId)
                                        .setWhereClause("ID='"+ previousId +"'"));
                    }
                    previousId = credentialId;
                }
            }

            confirmationMessage.append("Executed " + statements.size() + " statements in CREDENTIAL table");

        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when updating data from previous version", e);
        }
    }

    @Override
    protected String getTaskId() {
        return "Update 7.0.0";
    }
}
