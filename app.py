import random
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import string
from flask import Flask, jsonify, make_response, request
import pandas as pd
from hashlib import sha256
from sqlalchemy import (
    create_engine,
    Integer,
    Column,
    String,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from google.oauth2 import service_account
from google.auth.transport.requests import Request

app = Flask(__name__)
# limiter = Limiter(
#     get_remote_address, app=app, default_limits=["200 per day", "100 per hour"]
# )
CORS(app)

# Database For check connection and save reports names
Base = declarative_base()


class UserAccess(Base):
    __tablename__ = "UserAccess"
    user_id = Column(
        Integer,
        nullable=False,
        primary_key=True,
        autoincrement=True,
    )
    repositoryURL = Column(String, nullable=False)
    password_hashed = Column(String, nullable=False)
    salt = Column(String, nullable=False)


# Initialize the engine and create a session
engine = create_engine("sqlite:///app.db")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


def get_access_token():
    scopes = ["https://www.googleapis.com/auth/drive.readonly"]
    creds = service_account.Credentials.from_service_account_info(
        {
            "type": "service_account",
            "project_id": "my-cyber-project-432418",
            "private_key_id": "e2cdc7dbcf59baf420649f41bc3ea888b148a3b0",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCf1Y8QIx44pS5S\n9s/b7T5UeRBpJVHX9gsAQvOM1w7TVHzwthUwpYryiclA30qS9g2Yfm0R85zCYu4y\nGgVnuZB9MaEAOTY5vuuWb0DESFo4jrM9VdjmHDO3oPTEEF+/1sl1eTpNbV0FjcMZ\n6PjUQyZ1m7Mihjyy8ucYTyGB+YaMLLjuRSurL9q8lMlr60dJ6XlXjRJ0tnVYZJ9r\nDgySmeBLQeLJ5aOHbbzhwj7oHHdeKBd9gCKjrXuvZ3B97iOU8mn3gCogTCi9K+FY\ntgW8ECZqBq1qAw3JIZ78DFb3vVEmZGOxXUn4kUDD58kYpdrx7dO7DwKnu5VZiUSS\nyRpCJsDXAgMBAAECggEAISrAOrGG4mtIfxfPT0xeTEopASCo6J8abk32Wyn/XhQg\nrxShtgwMFsNH22nagD+F17iYaoq6Y04DLqtepsUHeiszxSeaHIaFPZzNfE2lRyo5\ngIdRcIK2qqrAT/Uz4UuxV2q2Ef4ZOP9PVo+VHvrmPq52EDp52wpzsQQuqFl+tZR3\n1jdq0nFWzCqT2blb5X5iIntzuzGzjIQxkmXOqab+JVkEoxM7YbJQjC+vWu9nBwa2\nPKncoCnIw3tUZQkKH2o4wrARm0uBQ6CtNzh8qs4BbQWcUoEdGNxdqzBFP/MFFn2c\nl7yMdSfQknCZY2BVg7+xPZZuWs4IbcskwrgzKRbL2QKBgQDflf0mm6pJd+9XBtvN\n+g5gdfGQu0PCKb1As3Lsm31paUVQBqjfXjq3Z6bLWu2hsNEr6LITWWJz3g/eN1Ei\ntcYaUrTRK4RJbobGYj+vWCGJdNzCriVCgi9p7UHb+1NyIHHRmdTIC2fg/6SVOIYw\nGGMBvivpsXWFzmm5pGCzLERZbwKBgQC3AYjXGpsuu4+tI7VNt8Kh+KC59+rg68az\nhMOWHcOIfIVeg6bQNbRNMn7aFbNlQpxxSsR0NNXN1/KXV5M9dViji4RAlNTjXIAs\n1pkzuFYt/QWsf7IqwQpsj1ojfKOauCcWs7cTMtDGCxN1TxabBsXhp1skAePs93SK\n3jNu/uHLGQKBgFnDNrH0VuZN/0m6GC7WkEULtOK9O9PMvA0ovh/dwPi76bbaJZwf\nkYUmWOFVbQe4HBH7xtpbzVnlMgutu6YqwhC5WZyMUvzEIdmtghHcWQJ9Z0/FaHIO\nIAjv1rwBZ5vvCKL0lmeFpLvBBotd+QmAEOeXOLwGob8JgoqkQqpMQFiDAoGAd6S7\nL9YnKlBZSFqWB69hwb7oZWyd1FqQ14Cu1g+zbCHsl7P+dRUHQYkHwdB6LnN0D+VP\ntqFsPl02LpeEnaOARbvKxOYIoHQzIB1Un6mePgazlOkPNEBsbjjyN00fMOHAPGlW\nAWkxcKiBGiqQnt24tSRSw6Gwv5WwTbGjcqeUOtECgYByDfTN0ZtzeDkJ7eKAIBUQ\nXgWM5Syd3UuLkZ9CQudOQCaKx5CUFTNFjmEa7SOjcZwHqUKZkU7GrmUr/+f4IVaP\nOVAMwCr1cn3rwiUvPDFQ4vXn/+0PhCsM9gStOe6eBDthgZ+rjtmVlx78YKt1JpDu\nOUADgT+vr12MfBgJ8NW7ug==\n-----END PRIVATE KEY-----\n",
            "client_email": "cyberproject24@my-cyber-project-432418.iam.gserviceaccount.com",
            "client_id": "112328416381903666415",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/cyberproject24%40my-cyber-project-432418.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com",
        },
        scopes=scopes,
    )
    creds.refresh(Request())
    return creds.token


def user_existences(repository_url, user_id):
    repository_url = str(repository_url)
    user_id = int(user_id)
    with Session() as session:
        query = (
            session.query(UserAccess)
            .filter_by(repositoryURL=repository_url, user_id=user_id)
            .first()
        )
        return query if query else False


def create_salt():
    my_dict = [
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "0",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "x",
        "y",
        "z",
    ]
    my_salt = ""
    for i in range(32):
        my_salt += str(my_dict[random.randint(0, my_dict.__len__() - 1)])
    return my_salt


# this for pre-push.py to answer
@app.route("/user-create", methods=["GET"])
# @limiter.limit("5 per minute")
def add_user():
    repositoryURL = request.args.get("repositoryUrl")
    password = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
    salt = create_salt()
    password_hashed = sha256((password + salt).encode()).hexdigest()
    try:
        with Session() as session:
            # Create a new UserAccess instance
            new_user = UserAccess(
                repositoryURL=repositoryURL, password_hashed=password_hashed, salt=salt
            )
            session.add(new_user)
            session.commit()

            # Retrieve the user_id of the newly created user
            user_id = new_user.user_id

    except SQLAlchemyError as e:
        # Handle the exception and return an error response
        return make_response(f"Database error: {str(e)}", 500)

    return (
        jsonify(
            {"repositoryUrl": repositoryURL, "userId": user_id, "password": password}
        ),
        200,
    )


# This for UI-website check if the details are correct - if so return the user_id for the google cloud function
@app.route("/sign-In/connect", methods=["POST"])
# @limiter.limit("5 per minute")
def sign_in():
    print("sign in is here")
    data = request.json  # include a arr{repositoryURL, userName,password}
    repositoryURL = data["repositoryUrl"]
    user_id = data["userId"]
    password = str(data["password"])
    tmp_user = user_existences(user_id=user_id, repository_url=repositoryURL)
    if tmp_user is not False:
        salt = tmp_user.salt
        password_hashed = tmp_user.password_hashed
        print(tmp_user.user_id)
        if sha256((password + salt).encode()).hexdigest() == password_hashed:
            json_response = {"repositoryURL": repositoryURL, "userId": tmp_user.user_id}
            return make_response(jsonify(json_response), 200)
    return make_response("Something get wrong", 505)


@app.route("/drive/getToken", methods=["GET"])
# @limiter.limit("5 per minute")
def get_token():
    token = get_access_token()
    return make_response(jsonify({"access_token": token}), 200)


@app.route("/drive/folderId", methods=["GET"])
# @limiter.limit("5 per minute")
def get_folder_id():
    parentFolderId = "1PXIVaQIaGb80yX_wc99KyxuHslUiXpNh"
    return make_response(jsonify({"folderId": parentFolderId}), 200)


if __name__ == "__main__":
    app.run(debug=True)
