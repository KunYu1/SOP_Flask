docker run \
    --name mongoDB \
    --rm \
    -v "/$(pwd)"/data_mongoDB:/data/db \
    -d \
    -p 27017:27017 \
    -e MONGO_INITDB_ROOT_USERNAME=root \
    -e MONGO_INITDB_ROOT_PASSWORD=root \
    mongo:4.4