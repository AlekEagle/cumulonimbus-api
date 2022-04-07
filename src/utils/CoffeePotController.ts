export namespace Structs {
  export enum CoffeePotStates {
    OFF,
    SLEEP,
    IDLE,
    BREWING,
    ERROR,
    DISCONNECTED,
  }

  export enum CoffeePotBrewTypes {
    ESPRESSO,
    LATTE,
    CAPPUCCINO,
    BASIC,
  }

  export interface CoffeePot {
    id: string;
    name: string;
    location?: string;
    state: CoffeePotStates;
    lastHeating?: number;
    lastBrewing?: number;
    lastError?: number;
    lastConnected?: number;
    isConnected: boolean;
  }

  export interface BrewInfo {
    id: string;
    coffeePotID: string;
    progress: number;
    brewTime: number;
    brewTimeLeft: number;
    brewType: CoffeePotBrewTypes;
  }

  export enum CoffeePotEventTypes {
    CONNECTED,
    DISCONNECTED,
    BREW_BEGIN,
    BREW_END,
    ERROR,
    HEATING,
    ENTER_SLEEP,
    EXIT_SLEEP,
  }

  export interface CoffeePotEvent {
    id: string;
    coffeePotID: string;
    type: CoffeePotEventTypes;
    timestamp: number;
  }
}

export default {
  Structs,
};
