import { sequelize, init as initDB } from "./index.js";
import { Model, DataTypes } from "sequelize";

export default class Instruction extends Model {
  id: string;
  name: string;
  steps: string[];
  filename: string | null;
  fileContent: string;
  description: string;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  Instruction.init(
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      name: {
        type: DataTypes.STRING(64),
        allowNull: false,
      },
      steps: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: false,
      },
      filename: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      fileContent: {
        type: DataTypes.STRING(65536),
        allowNull: false,
      },
      description: {
        type: DataTypes.STRING,
        allowNull: false,
      },
    },
    {
      sequelize,
      tableName: "Instructions",
    }
  );
  try {
    await Instruction.sync();
    console.log("Instruction table synced with DB.");
  } catch (error) {
    console.error("Unable to sync Instruction table. Error: ", error);
  }
})();
