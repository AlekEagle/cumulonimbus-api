import { sequelize, init as initDB } from '.';
import { Model, DataTypes } from 'sequelize';

export default class Upload extends Model {
  filename: string;
  userID: string;
  size: number;
}

(async function () {
  await initDB();
  Upload.init(
    {
      filename: {
        type: DataTypes.STRING,
        primaryKey: true
      },
      userID: DataTypes.STRING(60),
      size: DataTypes.INTEGER
    },
    {
      sequelize,
      tableName: 'Uploads'
    }
  );
  try {
    await Upload.sync();
    console.log('Upload table synced with DB.');
  } catch (error) {
    console.error('Unable to sync Upload table. Error: ', error);
  }
})();
