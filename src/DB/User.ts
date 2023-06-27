import { sequelize, init as initDB } from "./index.js";
import { Model, DataTypes } from "sequelize";

export default class User extends Model {
  id: string;
  username: string;
  email: string;
  staff: boolean;
  password: string;
  domain: string;
  subdomain: string;
  bannedAt: string;
  sessions: {
    iat: number;
    exp: number;
    name: string;
  }[];
  verified: boolean;
}

(async function () {
  await initDB();
  User.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
      },
      username: DataTypes.STRING(60),
      email: DataTypes.STRING,
      staff: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      password: DataTypes.STRING(2000),
      domain: DataTypes.STRING,
      subdomain: DataTypes.STRING,
      bannedAt: DataTypes.DATE,
      sessions: DataTypes.ARRAY(DataTypes.JSONB),
      verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
    },
    {
      sequelize,
      tableName: "Users",
    }
  );
  try {
    await User.sync();
    console.log("User table synced with DB.");
  } catch (error) {
    console.error("Unable to sync User table. Error: ", error);
  }
})();
