import { sequelize, init as initDB } from "./index.js";
import { Model, DataTypes } from "sequelize";

export default class File extends Model {
  id: string;
  userID: string;
  size: number;
  displayName: string;
}

(async function () {
  await initDB();
  File.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
      },
      userID: DataTypes.STRING(60),
      size: DataTypes.INTEGER,
      displayName: DataTypes.STRING(500),
    },
    {
      sequelize,
      tableName: "Uploads",
    }
  );
  try {
    await File.sync();
    console.log("Upload table synced with DB.");
  } catch (error) {
    console.error("Unable to sync Upload table. Error: ", error);
  }
})();
