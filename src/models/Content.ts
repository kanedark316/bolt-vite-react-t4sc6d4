import mongoose from 'mongoose';

const contentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    required: true,
    enum: ['movie', 'tv-show', 'live-event']
  },
  description: {
    type: String,
    required: true
  },
  genre: {
    type: String,
    required: true
  },
  ageRating: {
    type: String,
    required: true
  },
  contentWarnings: [{
    type: String
  }],
  releaseYear: Number,
  duration: String,
  seasons: {
    type: Number,
    default: 1
  },
  episodes: {
    type: Number,
    default: 1
  },
  fileUrl: {
    type: String,
    required: true
  },
  thumbnailUrl: String,
  views: {
    type: Number,
    default: 0
  },
  favorites: {
    type: Number,
    default: 0
  },
  rating: {
    type: Number,
    default: 0
  },
  numberOfRatings: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt timestamp before saving
contentSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

const Content = mongoose.model('Content', contentSchema);

export default Content;