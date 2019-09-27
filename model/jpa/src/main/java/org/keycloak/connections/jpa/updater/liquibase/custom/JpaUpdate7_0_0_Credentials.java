package org.keycloak.connections.jpa.updater.liquibase.custom;

import liquibase.exception.CustomChangeException;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Table;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class JpaUpdate7_0_0_Credentials extends CustomKeycloakTask {

    @Override
    protected void generateStatementsImpl() throws CustomChangeException {
        String credentialTableName = database.correctObjectName("CREDENTIAL", Table.class);
        try (PreparedStatement statement = jdbcConnection.prepareStatement("SELECT ID, HASH_ITERATIONS, SALT, TYPE, VALUE, COUNTER, DIGITS, PERIOD, ALGORITHM FROM " + credentialTableName);
             ResultSet rs = statement.executeQuery()) {
            String previousId = null;
            while (rs.next()) {
                String hashIterations = rs.getString("HASH_ITERATIONS").trim();
                if (rs.wasNull()) {
                    hashIterations = "";
                }
                String salt = rs.getString("SALT").trim();
                if (rs.wasNull()) {
                    salt = "";
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

                statements.add(
                        new UpdateStatement(null, null, credentialTableName)
                                .addNewColumnValue("SECRET_DATA", "{\"value\":\"" + value + "\",\"salt\":\"" + salt + "\"}")
                                .addNewColumnValue("CREDENTIAL_DATA", "{\"hashIterations\":" + hashIterations + ",\"algorithm\":\"" + algorithm + "\"}")
                                .addNewColumnValue("TYPE", PasswordCredentialModel.TYPE)
                                .setWhereClause("TYPE='password'")
                );
                statements.add(
                        new UpdateStatement(null, null, credentialTableName)
                                .addNewColumnValue("SECRET_DATA", "{\"value\":\"" + value + "\"}")
                                .addNewColumnValue("CREDENTIAL_DATA", "{\"subType\":\"" + type + "\",\"digits\":" + digits + ",\"counter\":" + counter + ",\"algorithm\":\"" + algorithm + "\"}")
                                .addNewColumnValue("TYPE", OTPCredentialModel.TYPE)
                                .setWhereClause("TYPE='hotp'")
                );
                statements.add(
                        new UpdateStatement(null, null, credentialTableName)
                                .addNewColumnValue("SECRET_DATA", "{\"value\":\"" + value + "\"}")
                                .addNewColumnValue("CREDENTIAL_DATA", "{\"subType\":\"" + type + "\",\"digits\":" + digits + ",\"period\":" + period + ",\"algorithm\":\"" + algorithm + "\"}")
                                .addNewColumnValue("TYPE", OTPCredentialModel.TYPE)
                                .setWhereClause("TYPE='totp'")
                );

                statements.add(
                        new UpdateStatement(null, null, credentialTableName)
                                .addNewColumnValue("PREVIOUS_CREDENTIAL_LINK", previousId)
                .setWhereClause("ID='"+ rs.getString("ID") + "'"));
                if (previousId != null){
                    statements.add(
                            new UpdateStatement(null, null, credentialTableName)
                                    .addNewColumnValue("NEXT_CREDENTIAL_LINK", rs.getString("ID"))
                                    .setWhereClause("ID='"+ previousId +"'"));
                }

                previousId = rs.getString("ID");
                confirmationMessage.append("Updated " + statements.size() + " records in CREDENTIAL table");
            }
        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when updating data from previous version", e);
        }
    }

    @Override
    protected String getTaskId() {
        return "Update 7.0.0";
    }
}
