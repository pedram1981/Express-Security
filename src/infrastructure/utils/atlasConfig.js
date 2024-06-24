function configString() {
    const connctionString = {
      dbName: process.env.dbName,
      uri: process.env.mongoConnection,
    };
  
    return connctionString;
  }
  
  export { configString };
  