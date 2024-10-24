import mongoose from 'mongoose';

const analyticsSchema = new mongoose.Schema({
  contentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Content',
    required: true
  },
  views: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  favorites: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  ratings: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  dailyStats: [{
    date: Date,
    views: Number,
    favorites: Number,
    averageRating: Number
  }]
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

export default Analytics;