import { MongoClient } from "mongodb";
import mongoSanitize from "mongo-sanitize";
import validator from "validator";

import { configString } from "../../../infrastructure/utils/atlasConfig.js";

export async function withDbConnection() {
  let client;
  try {
    const con = configString();
    client = await MongoClient.connect(
      con.uri,
      { useNewUrlParser: true, useUnifiedTopology: true, maxPoolSize: 10 },
    );

    return { success: true, outcome: { client } };
  } catch (error) {
    return { success: false, outcome: error.message };
  }
}

export async function insert(inputObject, collectioName, indexFeilds) {
  const { success, outcome } = await withDbConnection();
  if (success) {
    const { client } = outcome;
    try {
      const document = {};
      Object.keys(inputObject).forEach((key) => {
        document[key] = mongoSanitize(validator.escape(inputObject[key]));      
      });
      const indexObject = {};
      indexFeilds.forEach((value) => {
        indexObject[value] = 1;
      });
      const options = { unique: true };
      const database = client.db(process.env.dbName);
      const collection = database.collection(collectioName);
      collection.createIndex(indexObject, options);
      const result = await collection.insertOne(document);
      await client.close();
      if (result.acknowledged) return { success: true, outcome: "Opration successfully" };
      return { success: false, outcome: "Opration don't successfully" };
    } catch (error) {
      return { success: false, outcome: error.message };
    } finally {
      await client.close();
    }
  } else return { success, outcome };
}
