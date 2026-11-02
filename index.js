const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

/**
 * Callable Cloud Function: adminSetUserPassword
 *
 * Lets an Admin instantly set a NEW password for any other user account.
 * This is only possible server-side (Firebase Admin SDK) — the client SDK
 * can only ever change the CURRENTLY signed-in user's own password.
 *
 * Security:
 *  - Rejects unauthenticated calls.
 *  - Verifies the CALLER's own Firestore profile has role === 'Admin'
 *    before allowing the password change (checked server-side, so it
 *    cannot be bypassed by editing client-side JavaScript).
 *  - Requires the new password to be at least 6 characters (Firebase's
 *    own minimum).
 */
exports.adminSetUserPassword = functions.https.onCall(async (data, context) => {
  try {
    return await doSetPassword(data, context);
  } catch (err) {
    // Show the real reason in the app (and in the Firebase logs) instead of a bare "internal"
    if (err instanceof functions.https.HttpsError) throw err;
    console.error("adminSetUserPassword failed:", err);
    throw new functions.https.HttpsError("internal", "Server error: " + ((err && (err.code || err.message)) || String(err)));
  }
});

async function doSetPassword(data, context) {
  // 1. Must be logged in
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "You must be signed in to do this."
    );
  }

  // 2. Caller must be an Admin (checked from their Firestore profile)
  const callerSnap = await admin
    .firestore()
    .collection("users")
    .doc(context.auth.uid)
    .get();

  if (!callerSnap.exists || callerSnap.data().role !== "Admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only Admin users can change another user's password."
    );
  }

  // 3. Validate input
  const { targetUid, newPassword } = data || {};
  if (!targetUid || typeof targetUid !== "string") {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Missing target user."
    );
  }
  if (!newPassword || typeof newPassword !== "string" || newPassword.length < 6) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "New password must be at least 6 characters."
    );
  }

  // 4. Perform the password change via the Admin SDK
  try {
    const update = { password: newPassword };
    // The app signs people in with <EmployeeID>@emp.mphelpdesk.com (the "email" saved on their profile).
    // If the Auth account was created with a different email, the new password would never work
    // at the login screen - so bring the Auth email back in line with the profile.
    let profileEmail = "";
    try {
      const tSnap = await admin.firestore().collection("users").doc(targetUid).get();
      if (tSnap.exists) {
        const t = tSnap.data();
        profileEmail = String(t.email || "").trim().toLowerCase();
        if (!profileEmail && /^\d{3}$/.test(String(t.empId || ""))) profileEmail = t.empId + "@emp.mphelpdesk.com";
      }
    } catch (e) { /* profile lookup is best-effort */ }
    const before = await admin.auth().getUser(targetUid);
    if (profileEmail && (before.email || "").toLowerCase() !== profileEmail) update.email = profileEmail;
    update.disabled = false;
    const after = await admin.auth().updateUser(targetUid, update);
    return { success: true, loginEmail: after.email || "", emailFixed: !!update.email };
  } catch (err) {
    throw new functions.https.HttpsError(
      "internal",
      "Failed to update password: " + err.message
    );
  }
}
