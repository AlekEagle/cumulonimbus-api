import { sequelize, init as initDB } from "./index.js";
import { Model, DataTypes } from "sequelize";

export default class File extends Model {
  id: string;
  userID: string;
  size: number;
  name: string;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  File.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      userID: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      size: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING(256),
        allowNull: true,
      },
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
