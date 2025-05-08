const express = require('express');
const router = express.Router();
const admin = require('firebase-admin'); // déjà configuré dans ton projet

router.post('/save-ip', async (req, res) => {
    const { uid, ip } = req.body;

    if (!uid || !ip) {
        return res.status(400).json({ message: '❌ UID ou IP manquant' });
    }

    try {
        await admin.firestore().collection('user_ips').doc(uid).set({
            ip,
            timestamp: new Date()
        });
console.log("✅ IP enregistrée pour UID:", uid, "avec IP:", ip);

        return res.json({ message: '✅ IP enregistrée', uid, ip });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: '❌ Erreur serveur', error });
    }
});

module.exports = router;
