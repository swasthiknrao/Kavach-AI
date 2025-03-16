import tensorflow as tf
import numpy as np

class SecurityRL:
    def __init__(self):
        # Define state and action space sizes
        self.state_size = 10  # Size of input features
        self.action_size = 2  # Binary decision: Safe/Unsafe
        
        # Initialize other parameters
        self.learning_rate = 0.001
        self.gamma = 0.95  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.memory = []
        self.max_memory_size = 1000
        
        # Build and compile the model
        self.model = self.build_model()

    def build_model(self):
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, input_dim=self.state_size, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(self.action_size, activation='linear')
        ])
        
        model.compile(
            loss='mse',
            optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate)
        )
        return model

    def remember(self, state, action, reward, next_state, done):
        """Store experience in memory"""
        self.memory.append((state, action, reward, next_state, done))
        if len(self.memory) > self.max_memory_size:
            self.memory.pop(0)

    def act(self, state):
        """Choose action using epsilon-greedy policy"""
        if np.random.rand() <= self.epsilon:
            return np.random.randint(self.action_size)
        
        state = np.reshape(state, [1, self.state_size])
        act_values = self.model.predict(state)
        return np.argmax(act_values[0])

    def replay(self, batch_size=32):
        """Train on experiences from memory"""
        if len(self.memory) < batch_size:
            return
        
        minibatch = np.random.choice(len(self.memory), batch_size, replace=False)
        states = []
        targets = []
        
        for idx in minibatch:
            state, action, reward, next_state, done = self.memory[idx]
            state = np.reshape(state, [1, self.state_size])
            next_state = np.reshape(next_state, [1, self.state_size])
            
            target = reward
            if not done:
                target = reward + self.gamma * np.amax(
                    self.model.predict(next_state)[0]
                )
            
            target_f = self.model.predict(state)
            target_f[0][action] = target
            
            states.append(state[0])
            targets.append(target_f[0])
        
        self.model.fit(
            np.array(states), 
            np.array(targets), 
            epochs=1, 
            verbose=0
        )
        
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

    def predict_security(self, state):
        """Make security prediction for a given state"""
        state = np.reshape(state, [1, self.state_size])
        return self.model.predict(state)[0] 