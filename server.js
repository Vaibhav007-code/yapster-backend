const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);

// Check for JWT_SECRET environment variable
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('WARNING: JWT_SECRET environment variable is not set. Using fallback for development only.');
  // Only use this fallback for development!
  JWT_SECRET = 'dev_secret_key_do_not_use_in_production';
}

// More permissive CORS configuration to ensure mobile app can connect
const corsOptions = {
  origin: true, // Allow all origins
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));

// Configure Socket.IO with more permissive CORS
const io = socketIo(server, {
  cors: {
    origin: true, // Allow all origins
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
  },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 5e6,
  pingTimeout: 60000,
  pingInterval: 25000
});

app.use(express.json({ limit: '5mb' }));

const users = {};
const rooms = {};
const privateMessages = {};
const onlineUsers = {};

// Enhanced debugging endpoints
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

app.get('/debug/env', (req, res) => {
  res.status(200).json({
    jwt_secret_exists: !!process.env.JWT_SECRET,
    port: process.env.PORT,
    node_env: process.env.NODE_ENV,
    server_time: new Date().toISOString()
  });
});

app.options('*', cors()); // Enable pre-flight for all routes

app.get('/cors-test', (req, res) => {
  res.status(200).json({
    message: 'CORS test successful',
    origin: req.headers.origin || 'No origin header',
    headers: req.headers,
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => res.status(200).json({ 
  status: 'healthy',
  timestamp: new Date().toISOString() 
}));

app.get('/', (req, res) => {
  res.status(200).send('Server is running. API endpoints available at /api/*');
});

// Improved error handling for registration
app.post('/register', async (req, res) => {
  try {
    console.log('Registration attempt:', req.body);
    const { username, password } = req.body;
    
    if (!username || !password) {
      console.log('Missing username or password');
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (users[username]) {
      console.log('Username already exists:', username);
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    console.log('User registered successfully:', username);
    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Server error during registration', details: error.message });
  }
});

// Improved error handling for login
app.post('/login', async (req, res) => {
  try {
    console.log('Login attempt:', req.body);
    const { username, password } = req.body;
    
    if (!username || !password) {
      console.log('Missing username or password');
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = users[username];
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('Invalid password for user:', username);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    console.log('Login successful:', username);
    return res.status(200).json({ token, username });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error during login', details: error.message });
  }
});

// Improved token authentication middleware
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    console.log('Auth header:', authHeader);
    
    if (!authHeader) {
      console.log('No auth header provided');
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token) {
      console.log('No token in auth header');
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      
      req.user = user;
      console.log('Token authenticated for user:', user.username);
      next();
    });
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(500).json({ error: 'Server error during authentication' });
  }
};

app.get('/api/rooms', authenticateToken, (req, res) => {
  try {
    const roomList = Object.keys(rooms).map(name => ({
      name,
      isPrivate: rooms[name].isPrivate,
      creator: rooms[name].creator,
      members: rooms[name].members || [],
      admins: rooms[name].admins || []
    }));
    console.log(`Rooms list fetched by ${req.user.username}, found ${roomList.length} rooms`);
    res.status(200).json({ rooms: roomList });
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).json({ error: 'Server error fetching rooms' });
  }
});

app.post('/api/rooms', authenticateToken, (req, res) => {
  try {
    const { name, isPrivate, password, creator } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Room name is required' });
    }
    
    if (rooms[name]) {
      return res.status(400).json({ error: 'Room already exists' });
    }
    
    const roomCreator = creator || req.user.username;
    
    rooms[name] = {
      isPrivate: Boolean(isPrivate),
      password: isPrivate ? password : null,
      messages: [],
      creator: roomCreator,
      members: [roomCreator],
      admins: [roomCreator]
    };
    
    console.log(`Room created: ${name} by ${roomCreator}`);
    io.emit('room_created', { name, isPrivate: Boolean(isPrivate), creator: rooms[name].creator });
    return res.status(201).json({ message: 'Room created successfully' });
  } catch (error) {
    console.error('Error creating room:', error);
    res.status(500).json({ error: 'Server error creating room' });
  }
});

app.delete('/api/rooms/:roomName', authenticateToken, (req, res) => {
  try {
    const { roomName } = req.params;
    const { username } = req.user;
    
    if (!rooms[roomName]) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    if (!rooms[roomName].admins.includes(username)) {
      return res.status(403).json({ error: 'Only admin can delete room' });
    }
    
    delete rooms[roomName];
    console.log(`Room deleted: ${roomName} by ${username}`);
    io.emit('room_deleted', { roomName });
    return res.status(200).json({ message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Error deleting room:', error);
    res.status(500).json({ error: 'Server error deleting room' });
  }
});

app.post('/api/rooms/kick', authenticateToken, (req, res) => {
  try {
    const { roomName, username } = req.body;
    const admin = req.user.username;
    
    if (!rooms[roomName]) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    if (!rooms[roomName].admins.includes(admin)) {
      return res.status(403).json({ error: 'Only admin can kick users' });
    }
    
    if (rooms[roomName].admins.includes(username)) {
      return res.status(403).json({ error: 'Cannot kick another admin' });
    }
    
    rooms[roomName].members = rooms[roomName].members.filter(member => member !== username);
    
    if (onlineUsers[username]) {
      io.to(onlineUsers[username]).emit('kicked_from_room', { roomName });
    }
    
    console.log(`User ${username} kicked from ${roomName} by ${admin}`);
    io.to(roomName).emit('user_kicked', { username, roomName });
    return res.status(200).json({ message: 'User kicked successfully' });
  } catch (error) {
    console.error('Error kicking user:', error);
    res.status(500).json({ error: 'Server error kicking user' });
  }
});

const generateMessageId = () => uuidv4();

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  console.log('Connection headers:', socket.handshake.headers);
  let currentUser = null;
  
  // Enhanced ping handler for connection testing
  socket.on('ping', (callback) => {
    const response = {
      status: 'ok', 
      time: new Date().toISOString(),
      socketId: socket.id,
      user: currentUser || 'unknown'
    };
    
    if (typeof callback === 'function') {
      callback(response);
    } else {
      socket.emit('pong', response);
    }
  });
  
  socket.on('user_connected', ({ username, token }) => {
    try {
      console.log(`User connection attempt: ${username}`);
      
      if (!token) {
        console.error(`No token provided for user ${username}`);
        socket.emit('error', { message: 'Authentication failed: No token provided' });
        return;
      }
      
      jwt.verify(token, JWT_SECRET, (error, decoded) => {
        if (error) {
          console.error(`Token verification failed for ${username}:`, error);
          socket.emit('error', { message: 'Authentication failed: Invalid token' });
          return;
        }
        
        if (decoded.username !== username) {
          console.error(`Authentication failed for ${username}: token username mismatch`);
          socket.emit('error', { message: 'Authentication failed: Username mismatch' });
          return;
        }
        
        currentUser = username;
        onlineUsers[username] = socket.id;
        console.log(`User authenticated: ${username}`);
        io.emit('user_status_change', { username, status: 'online' });
        socket.emit('online_users', Object.keys(onlineUsers));
      });
    } catch (error) {
      console.error('Authentication error:', error);
      socket.emit('error', { message: 'Authentication failed: ' + error.message });
    }
  });

  socket.on('get_online_users', () => {
    socket.emit('online_users', Object.keys(onlineUsers));
  });

  socket.on('join_room', ({ roomName, password }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required to join room' });
        return;
      }
      
      if (!rooms[roomName]) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      if (rooms[roomName].isPrivate && !rooms[roomName].members.includes(currentUser)) {
        if (password !== rooms[roomName].password) {
          socket.emit('error', { message: 'Invalid password for private room' });
          return;
        }
      }
      
      if (!rooms[roomName].members.includes(currentUser)) {
        rooms[roomName].members.push(currentUser);
      }
      
      socket.join(roomName);
      console.log(`User ${currentUser} joined room ${roomName}`);
      socket.emit('room_joined', { room: roomName });
      socket.to(roomName).emit('user_joined_room', { username: currentUser, room: roomName });
      socket.emit('room_history', { messages: rooms[roomName].messages || [] });
      socket.emit('room_members', { 
        members: rooms[roomName].members || [],
        admins: rooms[roomName].admins || []
      });
    } catch (error) {
      console.error(`Error joining room ${roomName}:`, error);
      socket.emit('error', { message: 'Failed to join room: ' + error.message });
    }
  });

  socket.on('invite_to_room', ({ roomName, username }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required to invite users' });
        return;
      }
      
      if (!rooms[roomName]) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      if (!rooms[roomName].admins.includes(currentUser)) {
        socket.emit('error', { message: 'Only admin can invite users' });
        return;
      }
      
      if (!onlineUsers[username]) {
        socket.emit('error', { message: 'User is not online' });
        return;
      }
      
      if (!rooms[roomName].members.includes(username)) {
        rooms[roomName].members.push(username);
      }
      
      console.log(`User ${username} invited to room ${roomName} by ${currentUser}`);
      io.to(onlineUsers[username]).emit('room_invite', { roomName, admin: currentUser });
    } catch (error) {
      console.error(`Error inviting user to room ${roomName}:`, error);
      socket.emit('error', { message: 'Failed to invite user: ' + error.message });
    }
  });

  socket.on('kick_from_room', ({ roomName, username }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required to kick users' });
        return;
      }
      
      if (!rooms[roomName]) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      if (!rooms[roomName].admins.includes(currentUser)) {
        socket.emit('error', { message: 'Only admin can kick users' });
        return;
      }
      
      if (rooms[roomName].admins.includes(username)) {
        socket.emit('error', { message: 'Cannot kick another admin' });
        return;
      }
      
      rooms[roomName].members = rooms[roomName].members.filter(member => member !== username);
      
      if (onlineUsers[username]) {
        io.to(onlineUsers[username]).emit('kicked_from_room', { roomName });
      }
      
      console.log(`User ${username} kicked from room ${roomName} by ${currentUser}`);
      io.to(roomName).emit('user_kicked', { username, roomName });
      socket.emit('success', { message: 'User kicked successfully' });
    } catch (error) {
      console.error(`Error kicking user from room ${roomName}:`, error);
      socket.emit('error', { message: 'Failed to kick user: ' + error.message });
    }
  });

  socket.on('get_room_members', ({ roomName }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required to get room members' });
        return;
      }
      
      if (rooms[roomName]) {
        socket.emit('room_members', { 
          members: rooms[roomName].members || [],
          admins: rooms[roomName].admins || []
        });
      } else {
        socket.emit('error', { message: 'Room does not exist' });
      }
    } catch (error) {
      console.error(`Error getting room members for ${roomName}:`, error);
      socket.emit('error', { message: 'Failed to get room members: ' + error.message });
    }
  });

  socket.on('room_message', ({ roomName, message }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required' });
        return;
      }
      
      if (!rooms[roomName]) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      if (!rooms[roomName].members.includes(currentUser)) {
        socket.emit('error', { message: 'You are not a member of this room' });
        return;
      }
      
      const messageData = {
        id: generateMessageId(),
        text: message.text,
        media: message.media,
        sender: currentUser,
        timestamp: message.timestamp || new Date().toISOString()
      };
      
      rooms[roomName].messages.push(messageData);
      console.log(`New message in room ${roomName} from ${currentUser}`);
      io.to(roomName).emit('new_room_message', { room: roomName, message: messageData });
    } catch (error) {
      console.error(`Error sending room message to ${roomName}:`, error);
      socket.emit('error', { message: 'Failed to send message: ' + error.message });
    }
  });

  socket.on('get_private_messages', ({ otherUser }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required' });
        return;
      }
      
      if (!privateMessages[currentUser]) {
        privateMessages[currentUser] = {};
      }
      
      if (!privateMessages[currentUser][otherUser]) {
        privateMessages[currentUser][otherUser] = [];
      }
      
      console.log(`Private messages requested between ${currentUser} and ${otherUser}`);
      socket.emit('private_message_history', { 
        messages: privateMessages[currentUser][otherUser] || [] 
      });
    } catch (error) {
      console.error(`Error getting private messages with ${otherUser}:`, error);
      socket.emit('error', { message: 'Failed to get private messages: ' + error.message });
    }
  });

  socket.on('private_message', ({ recipient, message }) => {
    try {
      if (!currentUser) {
        socket.emit('error', { message: 'Authentication required' });
        return;
      }
      
      const messageData = {
        id: generateMessageId(),
        text: message.text,
        media: message.media,
        sender: currentUser,
        recipient: recipient,
        timestamp: message.timestamp || new Date().toISOString()
      };
      
      if (!privateMessages[currentUser]) {
        privateMessages[currentUser] = {};
      }
      if (!privateMessages[currentUser][recipient]) {
        privateMessages[currentUser][recipient] = [];
      }
      privateMessages[currentUser][recipient].push(messageData);
      
      if (!privateMessages[recipient]) {
        privateMessages[recipient] = {};
      }
      if (!privateMessages[recipient][currentUser]) {
        privateMessages[recipient][currentUser] = [];
      }
      privateMessages[recipient][currentUser].push(messageData);
      
      console.log(`Private message sent from ${currentUser} to ${recipient}`);
      socket.emit('private_message', messageData);
      
      const recipientSocketId = onlineUsers[recipient];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('private_message', messageData);
      }
    } catch (error) {
      console.error(`Error sending private message to ${recipient}:`, error);
      socket.emit('error', { message: 'Failed to send private message: ' + error.message });
    }
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}, User: ${currentUser}`);
    if (currentUser) {
      delete onlineUsers[currentUser];
      io.emit('user_status_change', { username: currentUser, status: 'offline' });
    }
  });

  socket.on('error', (error) => {
    console.error('Socket error for client:', socket.id, error);
  });
});

// Add additional error handlers
server.on('error', (error) => {
  console.error('Server error:', error);
});

server.on('upgrade', (request, socket, head) => {
  io.engine.handleUpgrade(request, socket, head, (ws) => {
    io.engine.emit('connection', ws, request);
  });
});

// Special configuration for Fly.io
// Fly.io uses PORT 8080 by default, but we'll check for PORT env var as well
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} at ${new Date().toISOString()}`);
  console.log(`Server environment: ${process.env.NODE_ENV || 'development'}`);
});