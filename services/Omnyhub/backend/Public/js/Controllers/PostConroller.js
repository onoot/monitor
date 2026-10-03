import PostModel from "../models/Post.js";
import mongoose from 'mongoose';


export const getAll = async(req,res)=>{
    try {
        const posts = await PostModel.find().populate('user','fullName').exec();

        res.json(posts);
    } catch(err){
        console.log(err);
        res.status(500).json({
            message: "Не удалось получить статьи"
        });
    }
};

export const getByUser = async (req, res) => {
  try {
    const { id } = req.params;
    const posts = await PostModel.find({ user: id }).populate('user','fullName').sort({ createdAt: -1 }).lean();
    return res.json(posts);
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: 'Не удалось получить статьи пользователя' });
  }
};

export const getOne = async (req, res) => {
    try {
      const postId = req.params.id;
  
    PostModel.findOneAndUpdate(
    {
      _id: postId,
    },
    {
      $inc: { viewsCount: 1 },
    },
    {
      returnDocument: "after",
    }
  ).then((doc, err) => {
    if (err) {
      console.log(err);
      return res.status(500).json({
        message: "Не удалось вернуть статью",
      });
    }
    if (!doc) {
      return res.status(404).json({
        message: "Статья не найдена",
      });
    }
    res.json(doc);
  });
  } catch (err) {
  console.log(err);
  res.status(500).json({
    message: "Ошибка",
    });
   }
};

export const create = async(req,res)=>{
    try {
        if (!req.userId || !mongoose.Types.ObjectId.isValid(req.userId)){
            return res.status(401).json({ message: 'Нет доступа' });
        }
        const doc = new PostModel({
            title: req.body.title,
            text: req.body.text,
            imageURL: req.body.imageURL,
            tags: req.body.tags,
            prise: req.body.prise,
            user: req.userId,
        });

        const post = await doc.save();

        res.json(post);
    } catch (err) {
        console.log('Create post error:', err.message);
        res.status(500).json({
            message: "Не удалось создать обЪявление"
        });
    }
};

export const remove = async (req, res) => {
  try {
    const postId = req.params.id;
    const doc = await PostModel.findOneAndDelete({ _id: postId, user: req.userId });

    if (!doc) {
      return res.status(404).json({ message: 'Статья не найдена или нет прав' });
    }

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err); 
    return res.status(500).json({
      message: 'Не удалось удалить статью', 
    });
  }
};

export const update = async(req,res)=>{
  try {
    const postId = req.params.id;

    const result = await PostModel.updateOne({
      _id: postId,
      user: req.userId,
    },{
      title: req.body.title,
      text: req.body.text,
      imageURL: req.body.imageURL,
      tags: req.body.tags,
      prise: req.body.prise,
      user: req.userId,
    });
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Статья не найдена или нет прав' });
    }
    res.json({ success: true });
  } catch(err){
    console.error(err);
    res.status(500).json({
      message: 'Не удалось обновить статью',
    });
  };
};
