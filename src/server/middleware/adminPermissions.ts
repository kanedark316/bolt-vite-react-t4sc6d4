import { Request, Response, NextFunction } from 'express';

interface AdminRequest extends Request {
  admin?: {
    adminId: string;
    role: string;
    permissions: {
      [key: string]: boolean;
    };
  };
}

export const checkPermission = (permission: string) => {
  return (req: AdminRequest, res: Response, next: NextFunction) => {
    if (!req.admin) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    if (!req.admin.permissions[permission]) {
      return res.status(403).json({ message: 'Permission denied' });
    }

    next();
  };
};