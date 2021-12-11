import { sequelize, init as initDB } from '.';
import { Model, DataTypes } from 'sequelize';

export default class Instruction extends Model {
  name: string;
  steps: string[];
  filename: string;
  fileContent: string;
  description: string;
  displayName: string;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  Instruction.init(
    {
      name: {
        type: DataTypes.STRING,
        primaryKey: true
      },
      steps: DataTypes.ARRAY(DataTypes.STRING(2000)),
      displayName: DataTypes.STRING,
      filename: DataTypes.STRING(500),
      fileContent: DataTypes.STRING(5000),
      description: DataTypes.STRING(300)
    },
    {
      sequelize,
      tableName: 'Instructions'
    }
  );
  try {
    await Instruction.sync();
    console.log('Instruction table synced with DB.');
  } catch (error) {
    console.error('Unable to sync Instruction table. Error: ', error);
  }
})();
