import { Cumulonimbus } from '../types';
import SessionEndpoints from './SessionEndpoints';
import UserEndpoints from './UserEndpoints';

const Endpoints: Cumulonimbus.APIEndpointModule[] = [
  UserEndpoints,
  SessionEndpoints
];

export default Endpoints;
