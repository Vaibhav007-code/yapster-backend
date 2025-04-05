const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true,
    allowedHeaders: ["Authorization"]
  },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 5e6,
  pingTimeout: 60000,
  pingInterval: 25000
});

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: '5mb' }));

const users = {};
const rooms = {};
const privateMessages = {};
const onlineUsers = {};

const JWT_SECRET = process.env.JWT_SECRET || 'e398e866a84cbfbda72c4e129e3115d1be990e9e9cb85f1182a1605d17ad8765';

app.get('/health', (req, res) => res.status(200).json({ status: 'healthy' }));

app.get('/', (req, res) => {
  res.status(200).send('Server is running');
});

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    if (users[username]) return res.status(400).json({ error: 'Username already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    const user = users[username];
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid username or password' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    return res.status(200).json({ token, username });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error during login' });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

app.get('/api/rooms', authenticateToken, (req, res) => {
  const roomList = Object.keys(rooms).map(name => ({
    name,
    isPrivate: rooms[name].isPrivate,
    creator: rooms[name].creator,
    members: rooms[name].members || [],
    admins: rooms[name].admins || []
  }));
  res.status(200).json({ rooms: roomList });
});

app.post('/api/rooms', authenticateToken, (req, res) => {
  const { name, isPrivate, password, creator } = req.body;
  if (!name) return res.status(400).json({ error: 'Room name is required' });
  if (rooms[name]) return res.status(400).json({ error: 'Room already exists' });
  
  rooms[name] = {
    isPrivate: Boolean(isPrivate),
    password: isPrivate ? password : null,
    messages: [],
    creator: creator || req.user.username,
    members: [creator || req.user.username],
    admins: [creator || req.user.username]
  };
  
  io.emit('room_created', { name, isPrivate: Boolean(isPrivate), creator: rooms[name].creator });
  return res.status(201).json({ message: 'Room created successfully', room: { name, isPrivate: Boolean(isPrivate), creator: rooms[name].creator } });
});

app.delete('/api/rooms/:roomName', authenticateToken, (req, res) => {
  const { roomName } = req.params;
  const { username } = req.user;
  
  if (!rooms[roomName]) return res.status(404).json({ error: 'Room not found' });
  if (!rooms[roomName].admins.includes(username)) return res.status(403).json({ error: 'Only admin can delete room' });
  
  delete rooms[roomName];
  io.emit('room_deleted', { roomName });
  return res.status(200).json({ message: 'Room deleted successfully' });
});

app.post('/api/rooms/kick', authenticateToken, (req, res) => {
  const { roomName, username } = req.body;
  const admin = req.user.username;
  
  if (!rooms[roomName]) return res.status(404).json({ error: 'Room not found' });
  if (!rooms[roomName].admins.includes(admin)) return res.status(403).json({ error: 'Only admin can kick users' });
  if (rooms[roomName].admins.includes(username)) return res.status(403).json({ error: 'Cannot kick another admin' });
  
  rooms[roomName].members = rooms[roomName].members.filter(member => member !== username);
  
  if (onlineUsers[username]) {
    io.to(onlineUsers[username]).emit('kicked_from_room', { roomName });
  }
  
  io.to(roomName).emit('user_kicked', { username, roomName });
  return res.status(200).json({ message: 'User kicked successfully' });
});

const generateMessageId = () => {
  return uuidv4();
};

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  let currentUser = null;
  
  socket.on('user_connected', ({ username, token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.username !== username) {
        socket.emit('error', { message: 'Authentication failed' });
        return;
      }
      currentUser = username;
      onlineUsers[username] = socket.id;
      io.emit('user_status_change', { username, status: 'online' });
      socket.emit('online_users', Object.keys(onlineUsers));
    } catch (error) {
      console.error('Authentication error:', error);
      socket.emit('error', { message: 'Authentication failed' });
    }
  });

  socket.on('get_online_users', () => {
    socket.emit('online_users', Object.keys(onlineUsers));
  });

  socket.on('join_room', ({ roomName, password }) => {
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
    socket.emit('room_joined', { room: roomName });
    socket.to(roomName).emit('user_joined_room', { username: currentUser, room: roomName });
    socket.emit('room_history', { messages: rooms[roomName].messages || [] });
    
    socket.emit('room_members', { 
      members: rooms[roomName].members || [],
      admins: rooms[roomName].admins || []
    });
  });

  socket.on('invite_to_room', ({ roomName, username }) => {
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
    io.to(onlineUsers[username]).emit('room_invite', { roomName, admin: currentUser });
  });

  socket.on('kick_from_room', ({ roomName, username }) => {
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
    
    io.to(roomName).emit('user_kicked', { username, roomName });
    socket.emit('success', { message: 'User kicked successfully' });
  });

  socket.on('get_room_members', ({ roomName }) => {
    if (rooms[roomName]) {
      socket.emit('room_members', { 
        members: rooms[roomName].members || [],
        admins: rooms[roomName].admins || []
      });
    } else {
      socket.emit('error', { message: 'Room does not exist' });
    }
  });

  socket.on('room_message', ({ roomName, message }) => {
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
    io.to(roomName).emit('new_room_message', { room: roomName, message: messageData });
  });

  socket.on('get_private_messages', ({ otherUser }) => {
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
    
    socket.emit('private_message_history', { 
      messages: privateMessages[currentUser][otherUser] || [] 
    });
  });

  socket.on('private_message', ({ recipient, message }) => {
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
    
    socket.emit('private_message', messageData);
    
    const recipientSocketId = onlineUsers[recipient];
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('private_message', messageData);
    }
  });

  socket.on('disconnect', () => {
    if (currentUser) {
      delete onlineUsers[currentUser];
      io.emit('user_status_change', { username: currentUser, status: 'offline' });
    }
  });

  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});