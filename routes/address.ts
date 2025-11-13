/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}