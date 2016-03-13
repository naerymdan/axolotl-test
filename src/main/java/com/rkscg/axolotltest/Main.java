/**
 * @Author Vincent
 */
package com.rkscg.axolotltest;

import com.rkscg.axolotltest.client.ClientRunnable;
import org.whispersystems.libaxolotl.InvalidKeyException;

import java.io.Console;
import java.lang.reflect.Field;
import java.security.PermissionCollection;
import java.security.Permission;
import java.util.Map;

public class Main {

    public static void main(String [] args) throws InvalidKeyException, InterruptedException {

        System.out.println("System - Booting up");

        removeCryptographyRestrictions();

        // Let's boot up 2 clients, Alice and Bob
        ClientRunnable alice = new ClientRunnable("Alice", 5);
        ClientRunnable bob   = new ClientRunnable("Bob",  28);

        Thread aliceThread = new Thread(alice);
        Thread bobThread   = new Thread(bob);

        aliceThread.start();
        bobThread.start();

        while (aliceThread.isAlive() && bobThread.isAlive()) {

            Thread.sleep(1000);
        }

        System.out.println("System - Execution stopping");
    }

    private static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            System.out.println("Cryptography restrictions removal not needed");
            return;
        }
        try {
        /*
         * Do the following, but with reflection to bypass access checks:
         *
         * JceSecurity.isRestricted = false;
         * JceSecurity.defaultPolicy.perms.clear();
         * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
         */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));

            System.out.println("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            System.out.println("Failed to remove cryptography restrictions");
        }
    }

    private static boolean isRestrictedCryptography() {
        // This simply matches the Oracle JRE, but not OpenJDK.
        return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
    }
}
