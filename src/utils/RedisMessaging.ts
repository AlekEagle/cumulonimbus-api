import logger from './LogMachine.js';

import { createClient } from 'redis';

export interface RedisMessagingOptions {
  host: string;
  port: number;
  user?: string;
  pass?: string;
}

export interface RedisMessagingPayload<T = any> {
  type: string;
  data: T;
  from: number;
}

export type RedisMessagingHandler<T = any> = (
  payload: RedisMessagingPayload<T>,
  channel: string,
) => void | Promise<void>;

export enum RedisMessagingErrorCode {
  CLIENT_CONNECTION_FAILED = 'CLIENT_CONNECTION_FAILED',
  CLIENT_SUBSCRIPTION_FAILED = 'CLIENT_SUBSCRIPTION_FAILED',
  CLIENT_PUBLISH_FAILED = 'CLIENT_PUBLISH_FAILED',
  CLIENT_DESERIALIZATION_FAILED = 'CLIENT_DESERIALIZATION_FAILED',
  CLIENT_HANDLE_FAILED = 'CLIENT_HANDLE_FAILED',
  UNKNOWN = 'UNKNOWN',
}

export class RedisMessagingError extends Error {
  name = 'RedisMessagingError';
  constructor(
    message: string,
    public code: RedisMessagingErrorCode,
    public subError?: Error,
  ) {
    super(message);
  }
}

export type RedisMessagingErrorHandler = (
  channel: string,
  error: RedisMessagingError,
  payload?: RedisMessagingPayload,
) => void | Promise<void>;

export default class RedisMessaging {
  protected client: ReturnType<typeof createClient>;
  protected ready;

  protected handlers: Map<string, RedisMessagingHandler[]> = new Map();
  protected errorHandlers: RedisMessagingErrorHandler[] = [];

  constructor(
    options?: RedisMessagingOptions,
    protected baseChannel: string = 'server:events',
    protected clientId: number = Number(process.env.INSTANCE!),
  ) {
    logger.debug(
      'Initializing RedisMessaging with base channel:',
      this.baseChannel,
    );
    this.client = createClient({
      socket: {
        host: options?.host,
        port: options?.port,
      },
      username: options?.user,
      password: options?.pass,
    });

    this.ready = Promise.all([
      this.client
        .connect()
        .then(() => true)
        .catch(() => false),
      this.client
        .subscribe(this.baseChannel, this.handleMessage.bind(this))
        .then(() => true)
        .catch(() => false),
    ]);
  }

  protected async waitUntilReady(): Promise<void> {
    const readyResult = await this.ready;
    if (!readyResult[0])
      throw new RedisMessagingError(
        'Redis client failed to connect.',
        RedisMessagingErrorCode.CLIENT_CONNECTION_FAILED,
      );
    if (!readyResult[1])
      throw new RedisMessagingError(
        'Redis client failed to subscribe.',
        RedisMessagingErrorCode.CLIENT_SUBSCRIPTION_FAILED,
      );
    return;
  }

  protected async handleMessage(data: string, channel: string): Promise<void> {
    try {
      logger.debug('Received message on channel:', channel, 'with data:', data);
      const payload: RedisMessagingPayload = JSON.parse(data);
      // Do not handle messages originating from this client instance.
      if (payload.from === this.clientId) return;
      try {
        const count = await this.emit(payload.type, payload);
        logger.debug(
          'Emitted message to',
          count,
          'handlers for type:',
          payload.type,
        );
      } catch (emitError) {
        logger.error('Error emitting message:', emitError);
        await this.handleError(
          channel,
          emitError as Error,
          RedisMessagingErrorCode.CLIENT_HANDLE_FAILED,
          payload,
        );
      }
    } catch (error) {
      logger.error('Failed to handle message:', error);
      await this.handleError(
        channel,
        error as Error,
        RedisMessagingErrorCode.CLIENT_DESERIALIZATION_FAILED,
      );
    }
  }

  protected async handleError(
    channel: string,
    error: Error,
    code: RedisMessagingErrorCode = RedisMessagingErrorCode.UNKNOWN,
    payload?: RedisMessagingPayload,
  ): Promise<void> {
    logger.error(
      'Handling error for channel:',
      channel,
      'with error:',
      error,
      'and payload:',
      payload,
    );
    const redisMessagingError =
      error instanceof RedisMessagingError
        ? error
        : new RedisMessagingError(error.message, code, error);
    try {
      await Promise.all(
        this.errorHandlers.map((handler) =>
          handler(channel, redisMessagingError, payload),
        ),
      );
    } catch (handlerError) {
      logger.error('Error handler failed:', handlerError);
    }
  }

  /**
   * Subscribes to a message type with the specified handler.
   * @param type The type of the message.
   * @param handler The handler to be called for the specified message type.
   */
  public on<T = any>(type: string, handler: RedisMessagingHandler<T>): void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, []);
    }
    this.handlers.get(type)!.push(handler);
  }

  /**
   * Subscribes to the error handler.
   * @param handler The error handler to be called when an error occurs.
   */
  public onError(handler: RedisMessagingErrorHandler): void {
    this.errorHandlers.push(handler);
  }

  /**
   * Oneshot subscription for a message type. The handler will be called only once.
   * @param type The type of the message.
   * @param handler The handler to be called once for the specified message type.
   */
  public once<T = any>(type: string, handler: RedisMessagingHandler<T>): void {
    const onceHandler: RedisMessagingHandler<T> = async (payload, channel) => {
      await handler(payload, channel);
      this.off(type, onceHandler);
    };
    this.on(type, onceHandler);
  }

  /**
   * Oneshot subscription for the error handler. The handler will be called only once.
   * @param handler The error handler to be called once when an error occurs.
   */
  public onceError(handler: RedisMessagingErrorHandler): void {
    const onceHandler: RedisMessagingErrorHandler = async (
      channel,
      error,
      payload,
    ) => {
      await handler(channel, error, payload);
      this.offError(onceHandler);
    };
    this.onError(onceHandler);
  }

  /**
   * Removes a listener for a specific message type. If no handler is provided, all listeners for the type will be removed.
   * @param type The type of the message.
   * @param handler The handler to remove. If not specified, all handlers for the type will be removed.
   * @returns void
   */
  public off<T = any>(type: string, handler?: RedisMessagingHandler<T>): void {
    if (!handler) {
      this.handlers.delete(type);
      return;
    }
    if (!this.handlers.has(type)) return;
    const handlers = this.handlers.get(type)!;
    const index = handlers.indexOf(handler);
    if (index !== -1) {
      handlers.splice(index, 1);
    }
  }

  /**
   * Removes a listener for the error handler. If no handler is provided, all error handlers will be removed.
   * @param handler The error handler to remove. If not specified, all error handlers will be removed.
   * @returns void
   */
  public offError(handler?: RedisMessagingErrorHandler): void {
    if (!handler) {
      this.errorHandlers = [];
      return;
    }
    const index = this.errorHandlers.indexOf(handler);
    if (index !== -1) {
      this.errorHandlers.splice(index, 1);
    }
  }

  /**
   * Gets the raw listeners for a specific message type.
   * @param type The type of the message.
   * @returns An array of raw listeners for the specified message type.
   */
  public rawListeners<T = any>(type: string): RedisMessagingHandler<T>[] {
    return this.handlers.get(type) || [];
  }

  /**
   * Gets the raw listeners for the error handler.
   * @returns An array of raw listeners for the error handler.
   */
  public rawErrorListeners(): RedisMessagingErrorHandler[] {
    return this.errorHandlers;
  }

  /**
   * Gets an object containing all raw listeners for all message types.
   * @returns An object where the keys are message types and the values are arrays of raw listeners for each type.
   */
  public rawListenersAll(): Record<string, RedisMessagingHandler[]> {
    const allListeners: Record<string, RedisMessagingHandler[]> = {};
    for (const [type, handlers] of this.handlers.entries()) {
      allListeners[type] = handlers;
    }
    return allListeners;
  }

  /**
   * Gets the number of listeners for a specific message type or all listeners if no type is specified.
   * @param type The type of the message. If not specified, the total number of listeners for all types will be returned.
   * @returns The number of listeners for the specified message type or all listeners if no type is specified.
   */
  public listenerCount(type?: string): number {
    if (type) {
      return (this.handlers.get(type) || []).length;
    }
    let count = 0;
    for (const handlers of this.handlers.values()) {
      count += handlers.length;
    }
    return count;
  }

  /**
   * Gets the number of listeners for the error handler.
   * @returns The number of listeners for the error handler.
   */
  public errorListenerCount(): number {
    return this.errorHandlers.length;
  }

  protected async emit(
    type: string,
    data: RedisMessagingPayload,
  ): Promise<number> {
    try {
      let count = (
        await Promise.all(
          this.rawListeners(type).map((handler) => handler(data, type)),
        )
      ).length;
      return count;
    } catch (error) {
      logger.error(`Error emitting message for type ${type}:`, error);
      return 0;
    }
  }

  /**
   * Publishes a message to the Redis channel.
   * @param type The type of the message.
   * @param data The payload of the message. MUST be serializable to JSON.
   */
  public async publish(type: string, data: any): Promise<void> {
    await this.waitUntilReady(); // Don't catch this, let it throw if not ready.
    const channel = this.baseChannel;
    const message = JSON.stringify({ type, data, from: this.clientId });
    logger.debug(
      'Publishing message to channel:',
      channel,
      'with data:',
      message,
    );
    try {
      await this.client.publish(channel, message);
    } catch (error) {
      throw new RedisMessagingError(
        'Failed to publish message',
        RedisMessagingErrorCode.CLIENT_PUBLISH_FAILED,
        error as Error,
      );
    }
  }
}
