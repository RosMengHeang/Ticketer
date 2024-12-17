// routes/eventRoutes.js

const express = require('express');
const Event = require('../models/Event');
const router = express.Router();

// POST route to create a new event
const eventRoutes = (upload) => {
  router.post('/events', upload.single('image'), async (req, res) => {
    try {
      const { title, date, location, description, ticketType, price, numberOfTickets } = req.body;
      const imagePath = req.file ? req.file.path : ''; // Handle image upload

      const event = new Event({
        title,
        date,
        location,
        description,
        image: imagePath,
        ticketType,
        price,
        numberOfTickets,
      });

      const savedEvent = await event.save(); // Save event to database
      res.status(201).json(savedEvent); // Respond with the created event
    } catch (error) {
      console.error(error); // Log the error for debugging
      res.status(500).json({ error: 'Failed to create event with image and ticket details' });
    }
  });

  // GET route to fetch all events
  router.get('/events', async (req, res) => {
    try {
      const events = await Event.find(); // Fetch all events from the database
      res.json(events); // Respond with the events
    } catch (error) {
      console.error(error); // Log the error for debugging
      res.status(500).json({ error: 'Failed to fetch events' });
    }
  });

  return router; // Return the configured router
};

module.exports = eventRoutes;
