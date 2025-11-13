/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { DeliveryModel } from '../models/delivery'
import * as security from '../lib/insecurity'

export function getDeliveryMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const methods = await DeliveryModel.findAll()
    if (methods) {
      const sendMethods = []
      for (const method of methods) {
        sendMethods.push({
          id: method.id,
          name: method.name,
          price: security.isDeluxe(req) ? method.deluxePrice : method.price,
          eta: method.eta,
          icon: method.icon
        })
      }
      res.status(200).json({ status: 'success', data: sendMethods })
    } else {
      res.status(400).json({ status: 'error' })
    }
  }
}

export function getDeliveryMethod () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!security.isAuthorized(req)) {
      return res.status(403).json({ status: 'error', message: 'Unauthorized access' })
    }
    const method = await DeliveryModel.findOne({ where: { id: req.params.id } })
    if (method != null) {
      // Check if the user is authorized to access this specific delivery method
      if (!security.isAuthorizedForDelivery(req, method)) {
        return res.status(403).json({ status: 'error', message: 'Unauthorized access to this delivery method' })
      }
      const sendMethod = {
        id: method.id,
        name: method.name,
        price: security.isDeluxe(req) ? method.deluxePrice : method.price,
        eta: method.eta,
        icon: method.icon
      }
      res.status(200).json({ status: 'success', data: sendMethod })
    } else {
      res.status(404).json({ status: 'error', message: 'Delivery method not found' })
    }
  }
}