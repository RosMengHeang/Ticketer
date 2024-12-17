const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: Date, required: true },
  location: { type: String, required: true },
  description: { type: String, required: true },
  imageUrl: { type: String },
  ticketType: { type: String, required: true },
  price: { type: Number, required: true },
  numberOfTickets: { type: Number, required: true },
});

module.exports = mongoose.model('Event', eventSchema);
