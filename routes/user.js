const express = require("express");
const router = express.Router();
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");
const uid2 = require("uid2");
const axios = require("axios");

const User = require("../models/User");

const isAuthenticated = require("../middlewares/isAuthenticated");
const { ObjectID, ObjectId } = require("mongodb");

const url = "https://api.websitecarbon.com/site?";

router.post("/user/signup", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.fields.email });
    if (!user) {
      const salt = uid2(16);
      const hash = SHA256(req.fields.password + salt).toString(encBase64);
      const token = uid2(16);

      const newUser = new User({
        email: req.fields.email,
        username: req.fields.username,
        websites: [],
        token: token,
        hash: hash,
        salt: salt,
      });

      await newUser.save();
      res.status(201).json({
        _id: newUser._id,
        token: newUser.token,
      });
    } else {
      res
        .status(409)
        .json("An account has already been created for this email address");
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.post("/user/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.fields.email });
    if (user) {
      const newHash = SHA256(req.fields.password + user.salt).toString(
        encBase64
      );
      if (newHash === user.hash) {
        res.status(200).json({
          _id: user._id,
          token: user.token,
          account: user.account,
        });
      } else {
        res.status(401).json({ message: "Unauthorized" });
      }
    } else {
      res.status(401).json({ message: "Unauthorized" });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.get("/users", async (req, res) => {
  try {
    const response = await User.find();
    res.status(200).json(response);
  } catch (error) {
    res.status(400).find({ message: error.message });
  }
});

router.get("/user/:id", async (req, res) => {
  try {
    const response = await User.findById(req.params.id);
    res.status(200).json(response);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.put("/user", isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    user.username = req.fields.username;
    await user.save();
    res.status(200).json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.put("/user/websites", isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const response = await axios.get(`${url}url=${req.fields.website}`, {
      headers: {
        "accept-encoding": "deflate",
      },
    });
    response.data.website_id = ObjectId();
    user.websites.push(response.data);
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.delete("/user", isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    await User.findByIdAndDelete(user._id);
    res.status(204).json("Deleted");
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

module.exports = router;
