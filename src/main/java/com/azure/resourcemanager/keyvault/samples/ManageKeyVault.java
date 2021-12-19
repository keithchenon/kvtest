// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.azure.resourcemanager.keyvault.samples;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.util.Configuration;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.keyvault.models.KeyPermissions;
import com.azure.resourcemanager.keyvault.models.PrivateEndpointServiceConnectionStatus;
import com.azure.resourcemanager.keyvault.models.SecretPermissions;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.core.management.Region;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.network.models.PrivateEndpoint;
import com.azure.resourcemanager.privatedns.models.PrivateDnsZone;
import com.azure.resourcemanager.resources.fluentcore.arm.models.PrivateEndpointConnection;
import com.azure.resourcemanager.samples.Utils;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

import java.util.List;

/**
 * Azure Key Vault sample for managing key vaults -
 *  - Create a key vault
 *  - Authorize an application
 *  - Update a key vault
 *    - alter configurations
 *    - change permissions
 *  - Create another key vault
 *  - List key vaults
 *  - Delete a key vault.
 */
public final class ManageKeyVault {

    /**
     * Main function which runs the actual sample.
     * @param azureResourceManager instance of the azure client
     * @param clientId client id
     * @return true if sample runs successfully
     */
    public static boolean runSample(AzureResourceManager azureResourceManager, String clientId) {
/*        final String vaultName1 = Utils.randomResourceName(azureResourceManager, "vault1", 20);

        final String vaultName2 = Utils.randomResourceName(azureResourceManager, "vault2", 20);
        final String rgName = Utils.randomResourceName(azureResourceManager, "rgNEMV", 24);
*/
        final String vaultName1 = "vaultn05";

        final String rgName = "REBELRG";
        try {
            //============================================================
            // Create a key vault with empty access policy

/*            System.out.println("Creating a key vault...");

            Vault vault1 = azureResourceManager.vaults().define(vaultName1)
                    .withRegion(Region.CANADA_CENTRAL)
                    .withNewResourceGroup(rgName)
                    .withEmptyAccessPolicy()
                    .create();

            System.out.println("Created key vault");
            Utils.print(vault1);*/
            System.out.println("modify private endpoint...");
            String subscriptionid = azureResourceManager.subscriptionId();
            String privateEndpointName= "REBELPEP005";
            String resourceGroup = "REBELRG";
            String vaultname= "vaultn05";
            String privateEndpointConnectionName= "REBELPEP005";
            String serviceResourceId="/subscriptions/"+subscriptionid+"/resourceGroups/"+resourceGroup+"/providers/Microsoft.KeyVault/vaults/"+vaultname;
            String connectionResourceId="/subscriptions/"+subscriptionid+"/resourceGroups/"+resourceGroup+"/providers/Microsoft.KeyVault/vaults/"+vaultname+"/privateEndpointConnections/"+privateEndpointName;
            Vault vault = azureResourceManager.vaults().getById(serviceResourceId);
            PrivateEndpoint.PrivateLinkServiceConnection conn = azureResourceManager.privateEndpoints().getById(connectionResourceId).privateLinkServiceConnections().get(privateEndpointConnectionName);
//            vault.approvePrivateEndpointConnection(privateEndpointConnectionName); // "REBELPEP06conn"
            Utils.print(vault);
            String status= azureResourceManager.privateEndpoints().getById(connectionResourceId).
                    privateLinkServiceConnections().get(privateEndpointConnectionName).state().status();
            System.out.println(status);

/*            String privateDnsName="rebelpdns.com";
            String privateDnsId="/subscriptions/"+subscriptionid+"/resourceGroups/"+resourceGroup+"/providers/Microsoft.Network/privateDnsZones/"+privateDnsName;
            String aRecordIPAddress= conn.parent().customDnsConfigurations().stream().findFirst().get().ipAddresses().get(0);
            PrivateDnsZone privateDnsZone = azureResourceManager.privateDnsZones().getById(privateDnsId);
            boolean dnsApprovalCheck = privateDnsZone.aRecordSets().list().stream().anyMatch(a-> aRecordIPAddress.equalsIgnoreCase(a.ipv4Addresses().get(0)));
            System.out.println(aRecordIPAddress);
            System.out.println(dnsApprovalCheck);*/
            //            System.out.println(conn.name());
/*

            //============================================================
            // Authorize an application

            System.out.println("Authorizing the application associated with the current service principal...");

            vault1 = vault1.update()
                    .defineAccessPolicy()
                        .forServicePrincipal(clientId)
                        .allowKeyAllPermissions()
                        .allowSecretPermissions(SecretPermissions.GET)
                        .allowSecretPermissions(SecretPermissions.LIST)
                        .attach()
                    .apply();

            System.out.println("Updated key vault");
            Utils.print(vault1);

            //============================================================
            // Update a key vault

            System.out.println("Update a key vault to enable deployments and add permissions to the application...");

            vault1 = vault1.update()
                    .withDeploymentEnabled()
                    .withTemplateDeploymentEnabled()
                    .updateAccessPolicy(vault1.accessPolicies().get(0).objectId())
                    .allowCertificatePermissions()
                        .allowSecretAllPermissions()
                        .parent()
                    .apply();

            System.out.println("Updated key vault");
            // Print the network security group
            Utils.print(vault1);


            //============================================================
            // Create another key vault

            Vault vault2 = azureResourceManager.vaults().define(vaultName2)
                    .withRegion(Region.US_EAST)
                    .withExistingResourceGroup(rgName)
                    .defineAccessPolicy()
                        .forServicePrincipal(clientId)
                        .allowKeyPermissions(KeyPermissions.LIST)
                        .allowKeyPermissions(KeyPermissions.GET)
                        .allowKeyPermissions(KeyPermissions.DECRYPT)
                        .allowSecretPermissions(SecretPermissions.GET)
                        .attach()
                    .create();

            System.out.println("Created key vault");
            // Print the network security group
            Utils.print(vault2);


            //============================================================
            // List key vaults

            System.out.println("Listing key vaults...");

            for (Vault vault : azureResourceManager.vaults().listByResourceGroup(rgName)) {
                Utils.print(vault);
            }

            //============================================================
            // Delete key vaults
            System.out.println("Deleting the key vaults");
            azureResourceManager.vaults().deleteById(vault1.id());
            azureResourceManager.vaults().deleteById(vault2.id());
            System.out.println("Deleted the key vaults");
*/
//            azureResourceManager.vaults().deleteById(vault1.id());

            return true;
        } finally {
/*            try {
                System.out.println("Deleting Resource Group: " + rgName);
                azureResourceManager.resourceGroups().beginDeleteByName(rgName);
                System.out.println("Deleted Resource Group: " + rgName);
            } catch (NullPointerException npe) {
                System.out.println("Did not create any resources in Azure. No clean up is necessary");
            } catch (Exception g) {
                g.printStackTrace();
            }*/
        }
    }
    /**
     * Main entry point.
     * @param args the parameters
     */
    public static void main(String[] args) {
        try {

            //=============================================================
            // Authenticate

/*            final AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);
            final TokenCredential credential = new DefaultAzureCredentialBuilder()
                .authorityHost(profile.getEnvironment().getActiveDirectoryEndpoint())
                .build();
            final Configuration configuration = Configuration.getGlobalConfiguration();*/
            String clientId= "";
            String clientSecret= "";
            String tenantId ="";
            ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .tenantId(tenantId)
                    .build();
/*            SecretClient client = new SecretClientBuilder()
                    .vaultUrl("https://vaultn5.vault.azure.net")
                    .credential(clientSecretCredential)
                    .buildClient();*/

            AzureResourceManager azureResourceManager = AzureResourceManager
                .configure()
                .withLogLevel(HttpLogDetailLevel.BASIC)
                .authenticate(clientSecretCredential,new AzureProfile(AzureEnvironment.AZURE))
                    .withTenantId(tenantId)
                .withDefaultSubscription();

            // Print selected subscription
            System.out.println("Selected subscription: " + azureResourceManager.subscriptionId());

            runSample(azureResourceManager, clientId);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private ManageKeyVault() {
    }
}
