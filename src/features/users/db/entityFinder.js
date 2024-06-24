import { MongoClient } from "mongodb";
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

export async function showProfile(email, collectioName) {
  const { success, outcome } = await withDbConnection();
  if (success) {
    const { client } = outcome;
    const database = client.db(process.env.dbName);

    const collection = database.collection(collectioName);
    try {
      const filter = { email };
      const projection = { projection: { password: 0, _id: 0 } };
      const result = await collection.findOne(filter, projection);
      await client.close();
      if (result) return { success: true, outcome: result };
      return { success: false, outcome: "-" };
    } catch (error) {
      await client.close();
      return { success: false, outcome: error.message };
    }
  } else return { success, outcome };
}

export async function login(email, password, collectioName) {
  const { success, outcome } = await withDbConnection();
  if (success) {
    const { client } = outcome;
    const database = client.db(process.env.dbName);

    const collection = database.collection(collectioName);
    try {
      const filter = { email, password };
      const result = await collection.findOne(filter);
      await client.close();
      if (result) return { success: true, outcome: result };
      return { success: false, outcome: "User not found or incorrect password" };
    } catch (error) {
      await client.close();
      return { success: false, outcome: error.message };
    }
  } else return { success, outcome };
}

