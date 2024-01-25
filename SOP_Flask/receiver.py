from pymongo import MongoClient
import socket
import json

USERNAME = 'root'
PASSWORD = 'root'
HOST = 'localhost'
PORT = '27017'

client = MongoClient(f"mongodb://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/")

# Create a database named "flask"
flaskDB = client["flask"] 
# Create a collection named "Heavyhitter" in database
HeavyhitterCollection = flaskDB["Heavyhitter"]

host = '0.0.0.0'
port = 12345
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print('Waiting connection...')
    while True:
        conn, addr = s.accept()
        print('Connection from：', addr)
        received_data = conn.recv(4096).decode('utf-8')
        received_dict = json.loads(received_data)
        received_dict = {int(key): value for key, value in received_dict.items()}
        # df_data = {'Destination': [], 'Source': [], 'Counter': []}
        HeavyhitterCollection.delete_many({})
        for key, value in received_dict.items():
            first_16_bits = (key >> 16) & 0xFFFF
            second_16_bits = key & 0xFFFF
            HeavyhitterCollection.insert_one({
                "input_port":first_16_bits,
                "output_port":second_16_bits,
                "number":value
            })