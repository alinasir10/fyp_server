import { Server } from "socket.io";
import type { Server as HttpServer } from "http";

class SocketInitializationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SocketInitializationError";
    }
}

class SocketIO {
    private static instance: Server | null = null;
    private static adminNamespace: ReturnType<Server["of"]> | null = null;
    private static isInitializing: boolean = false;

    // Initialize the Socket.IO server
    static init(httpServer: HttpServer): Server {
        if (!SocketIO.instance && !SocketIO.isInitializing) {
            try {
                SocketIO.isInitializing = true;

                SocketIO.instance = new Server(httpServer, {
                    cors: {
                        origin: ["http://localhost:3000", "https://admin.socket.io"],
                        methods: ["GET", "POST"],
                        credentials: true,
                    },
                });

                // Create admin namespace
                SocketIO.adminNamespace = SocketIO.instance.of("/admin");

                console.log("Socket.IO and admin namespace initialized successfully");
            } catch (error) {
                console.error("Failed to initialize Socket.IO:", error);
                throw new SocketInitializationError(
                  "Failed to initialize Socket.IO instance"
                );
            } finally {
                SocketIO.isInitializing = false;
            }
        }

        if (!SocketIO.instance) {
            throw new SocketInitializationError(
              "Socket.IO instance could not be initialized"
            );
        }

        return SocketIO.instance;
    }

    // Get the initialized instance of Socket.IO
    static getInstance(): Server {
        if (!SocketIO.instance) {
            throw new SocketInitializationError(
              "Socket.IO instance is not initialized. Please call SocketIO.init() first."
            );
        }
        return SocketIO.instance;
    }

    // Get the admin namespace
    static getAdminNamespace(): ReturnType<Server["of"]> {
        if (!SocketIO.adminNamespace) {
            throw new SocketInitializationError(
              "Admin namespace not initialized. Please call SocketIO.init() first."
            );
        }
        return SocketIO.adminNamespace;
    }

    // Emit an event to the admin namespace
    static emitToAdmin(event: string, data: any): boolean {
        try {
            const adminNamespace = this.getAdminNamespace();
            adminNamespace.emit(event, data);
            console.log(
              `Emitted event: ${event} to admin namespace with data:`,
              data
            );
            return true;
        } catch (error) {
            if (error instanceof SocketInitializationError) {
                console.warn(
                  `Skipping emission of event: ${event}, admin namespace not initialized.`
                );
            } else {
                console.error(`Error emitting event: ${event}`, error);
            }
            return false;
        }
    }

    // Check if Socket.IO is initialized
    static isInitialized(): boolean {
        return SocketIO.instance !== null;
    }

    // Clean up the Socket.IO instance
    static cleanup(): void {
        try {
            if (SocketIO.instance) {
                SocketIO.instance.close();
                SocketIO.instance = null;
                SocketIO.adminNamespace = null;
                console.log("Socket.IO cleaned up successfully");
            }
        } catch (error) {
            console.error("Error during Socket.IO cleanup:", error);
        }
    }
}

export default SocketIO;
