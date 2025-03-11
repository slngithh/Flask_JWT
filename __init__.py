import json
from flask import Flask, render_template, jsonify, request, make_response
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required,
    JWTManager, get_jwt, set_access_cookies, unset_jwt_cookies
)
from datetime import timedelta

app = Flask(__name__)

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Clé secrète
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # Expiration des jetons à 1 heure
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # Stocker les JWT dans les cookies
app.config["JWT_COOKIE_SECURE"] = False  # Mettre sur True en production si HTTPS
jwt = JWTManager(app)

# Base de données des utilisateurs (simulée)
users = {
    "test": {"password": "test", "role": "user"},
    "admin": {"password": "admin", "role": "admin"}
}

@app.route('/')
def home():
    return render_template('formulaire.html')  # Affiche le formulaire de connexion

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # ⚠️ Corrigé : `identity` doit être une chaîne de caractères
    access_token = create_access_token(identity=json.dumps({"username": username, "role": user["role"]}))
    
    response = jsonify({"msg": "Connexion réussie !"})
    set_access_cookies(response, access_token)  # Stocke le jeton dans un Cookie
    return response

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "Déconnexion réussie"})
    unset_jwt_cookies(response)  # Supprime le cookie contenant le jeton
    return response

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = json.loads(get_jwt_identity())  # ⚠️ Corrigé : Décoder le JSON
    return jsonify(logged_in_as=current_user), 200

@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    current_user = json.loads(get_jwt_identity())  # ⚠️ Corrigé : Décoder le JSON
    
    if current_user["role"] != "admin":
        return jsonify({"msg": "Accès refusé. Vous n'êtes pas administrateur."}), 403
    
    return jsonify({"msg": f"Bienvenue, {current_user['username']} ! Vous êtes administrateur."})

if __name__ == "__main__":
    app.run(debug=True)
