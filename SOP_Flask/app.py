from flask import Flask
import pymongo
from pymongo import MongoClient
from flask import render_template
from flask import jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)
USERNAME = 'root'
PASSWORD = 'root'
HOST = 'localhost'
PORT = '27017'

# Connect with mongo database
client = MongoClient(f"mongodb://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/")

# Create a database named "flask"
flaskDB = client["flask"] 

# Create a collection named "Heavyhitter" in database
HeavyhitterCollection = flaskDB["Heavyhitter"]

@socketio.on('get_update')
def handle_update():
    # Only deliver first 100 data 
    data_from_mongo = list(HeavyhitterCollection.find({}, {"_id": 0}).sort("number", pymongo.DESCENDING).limit(100))
    print("Received get_update event")
    emit('update_data', data_from_mongo)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/Heavyhitter")
def heavyhitter():
    # Only deliver first 100 data 
    data_from_mongo = list(HeavyhitterCollection.find({}, {"_id": 0}).sort("number", pymongo.DESCENDING).limit(100))
    print(data_from_mongo)
    return render_template("heavyhitter.html", data_mongo=data_from_mongo)

if __name__ == "__main__":
    HeavyhitterCollection.delete_many({})
    socketio.run(app, port=3000)
