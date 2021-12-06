import { Cumulonimbus } from '../types';
import UserSessionEndpoints from './user/UserSessionEndpoints';
import UserAccountEndpoints from './user/UserAccountEndpoints';
import UserFileEndpoints from './user/UserFileEndpoints';

const Endpoints: Cumulonimbus.APIEndpointModule[] = [
  UserAccountEndpoints,
  UserSessionEndpoints,
  UserFileEndpoints
];

export default Endpoints;
