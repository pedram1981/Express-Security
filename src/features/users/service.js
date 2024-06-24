import * as crud from "./db/entityCrud.js";
import * as find from "./db/entityFinder.js";

export const signOut = async (email, password, phone ,name) => {
    email=email.toLowerCase();
    const result=await crud.insert({name, email, password},"user",["email"]);
    return result;
  };

  export const login = async (email,password) => {
    email=email.toLowerCase();
    const result=await find.login(email,password, "user") ;
    return result;
  };

  export const profile = async (email) => {
    email=email.toLowerCase();
    const result=await find.showProfile(email,"user") ;
    return result;
  };

